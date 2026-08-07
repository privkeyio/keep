// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use keep_core::relay::MAX_AUTO_KINDS;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::types::{NIP98_HTTP_AUTH, NIP98_MAX_REMEMBER_SECS};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Permission: u32 {
        const GET_PUBLIC_KEY = 0b00000001;
        const SIGN_EVENT     = 0b00000010;
        const NIP04_ENCRYPT  = 0b00000100;
        const NIP04_DECRYPT  = 0b00001000;
        const NIP44_ENCRYPT  = 0b00010000;
        const NIP44_DECRYPT  = 0b00100000;
        const NIP44_V3_ENCRYPT = 0b01000000;
        const NIP44_V3_DECRYPT = 0b10000000;

        const DEFAULT = Self::GET_PUBLIC_KEY.bits();

        const ALL = Self::GET_PUBLIC_KEY.bits()
                  | Self::SIGN_EVENT.bits()
                  | Self::NIP04_ENCRYPT.bits()
                  | Self::NIP04_DECRYPT.bits()
                  | Self::NIP44_ENCRYPT.bits()
                  | Self::NIP44_DECRYPT.bits()
                  | Self::NIP44_V3_ENCRYPT.bits()
                  | Self::NIP44_V3_DECRYPT.bits();
    }
}

impl Permission {
    /// Canonical (flag, snake_case name) table. Single source of truth shared
    /// by the CLI parser/formatter, desktop UI, and any other caller.
    pub const NAMES: &'static [(Permission, &'static str)] = &[
        (Permission::GET_PUBLIC_KEY, "get_public_key"),
        (Permission::SIGN_EVENT, "sign_event"),
        (Permission::NIP04_ENCRYPT, "nip04_encrypt"),
        (Permission::NIP04_DECRYPT, "nip04_decrypt"),
        (Permission::NIP44_ENCRYPT, "nip44_encrypt"),
        (Permission::NIP44_DECRYPT, "nip44_decrypt"),
        (Permission::NIP44_V3_ENCRYPT, "nip44v3_encrypt"),
        (Permission::NIP44_V3_DECRYPT, "nip44v3_decrypt"),
    ];

    /// Resolve a single canonical name (snake_case, also accepts no-underscore
    /// aliases) to its `Permission` flag, or `None` if unknown. `"all"`
    /// returns `ALL`. Distinct from the bitflags-generated `from_name`, which
    /// only matches the all-caps constant names (`GET_PUBLIC_KEY`, ...).
    pub fn from_canonical_name(name: &str) -> Option<Permission> {
        let lower = name.to_ascii_lowercase();
        if lower == "all" {
            return Some(Permission::ALL);
        }
        for (flag, canonical) in Self::NAMES {
            if lower == *canonical || lower == canonical.replace('_', "") {
                return Some(*flag);
            }
        }
        None
    }

    /// Render this bitset as a comma-separated string of snake_case names,
    /// or `"(none)"` if no bits are set.
    pub fn to_names(self) -> String {
        let set: Vec<&str> = Self::NAMES
            .iter()
            .filter(|(flag, _)| self.contains(*flag))
            .map(|(_, n)| *n)
            .collect();
        if set.is_empty() {
            "(none)".to_string()
        } else {
            set.join(",")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionDuration {
    Session,
    Seconds(u64),
    Forever,
}

impl PermissionDuration {
    pub fn is_expired(&self, connected_at: Timestamp) -> bool {
        match self {
            Self::Session | Self::Forever => false,
            Self::Seconds(secs) => {
                let now = Timestamp::now().as_secs();
                let expires = connected_at.as_secs().saturating_add(*secs);
                now > expires
            }
        }
    }
}

/// What to do with a request without asking the user.
///
/// A boolean cannot carry this. "Do not prompt" is two different answers,
/// allow and refuse, and collapsing them is how a remembered refusal would
/// turn into a silent approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// A live grant covers it; proceed without prompting.
    Allow,
    /// A live refusal covers it; reject without prompting.
    Deny,
    /// Nothing on record; ask.
    Ask,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPermission {
    pub pubkey: PublicKey,
    pub name: String,
    pub permissions: Permission,
    /// Per-app, per-kind grants that never expire. Set via the
    /// `connect_auto_approve_kinds` startup config OR by the user picking
    /// "Forever" on the per-request prompt (#575).
    pub auto_approve_kinds: HashSet<Kind>,
    /// Per-app, per-kind grants with an explicit expiry (unix epoch seconds).
    /// Set by the user picking a timed remember-duration on the per-request
    /// prompt (#575). Skipped on read once `now() >= expiry`. `#[serde(skip)]`
    /// on direct `AppPermission` serialization, but the grants ARE persisted
    /// and restored out-of-band via the `StoredBunkerPermission` path: on save
    /// they are written to `StoredTimedKindGrant`, and `restore_persisted`
    /// reloads them, pruning any entry that expired while the bunker was down
    /// and excluding NIP-98 (kind 27235): a NIP-98 timed grant (#613) is
    /// remembered in memory for a short clamped window but is never persisted
    /// or restored across a restart.
    #[serde(skip)]
    pub timed_kind_grants: HashMap<Kind, u64>,
    /// Per-app, per-kind refusals with an explicit expiry (unix epoch seconds).
    ///
    /// The grant fields above answer "may this app do this without asking".
    /// This answers "has the user already said no, recently enough that asking
    /// again would be pestering them". Without it a rejection decides one
    /// request and nothing more, which is fine for a person, who stops asking,
    /// and wrong for an automated client, which retries: one refusal becomes a
    /// prompt every retry interval, and the only way to stop it is revoking the
    /// app outright, an answer far broader than the one being given.
    ///
    /// Not serialized, and deliberately not persisted in this change. A denial
    /// that survives a restart is a stronger instrument than the problem needs:
    /// within a session it stops the pestering completely, and after a restart
    /// the client asks once more and is told no once more.
    #[serde(skip)]
    pub timed_kind_denials: HashMap<Kind, u64>,
    pub connected_at: Timestamp,
    pub last_used: Timestamp,
    pub request_count: u64,
    #[serde(default = "default_duration")]
    pub duration: PermissionDuration,
    /// Set true when the user makes an explicit remember-decision for this app
    /// (`grant_kind_forever` / `grant_kind_for`), false for a bare connection or
    /// a client-supplied connect-time kind scope. Distinguishes a real user
    /// remember from a client's `sign_event:<kind>` connect request so only the
    /// former is persisted/restored across a bunker restart. Rebuilt from the
    /// persisted row on restore.
    #[serde(default)]
    pub explicitly_remembered: bool,
}

fn default_duration() -> PermissionDuration {
    PermissionDuration::Forever
}

impl AppPermission {
    pub fn new(pubkey: PublicKey, name: String) -> Self {
        Self {
            pubkey,
            name,
            permissions: Permission::DEFAULT,
            auto_approve_kinds: HashSet::from([Kind::Reaction]),
            timed_kind_grants: HashMap::new(),
            timed_kind_denials: HashMap::new(),
            connected_at: Timestamp::now(),
            last_used: Timestamp::now(),
            request_count: 0,
            duration: PermissionDuration::Forever,
            explicitly_remembered: false,
        }
    }

    /// Returns true if a timed grant exists for `kind` AND the grant has not
    /// expired. Expired entries are skipped here and garbage-collected by the
    /// next mutation through `prune_expired_kind_grants`.
    pub fn has_unexpired_timed_grant(&self, kind: Kind) -> bool {
        self.timed_kind_grants
            .get(&kind)
            .is_some_and(|expiry| now_unix_secs() < *expiry)
    }

    /// Whether a live refusal covers `kind`.
    pub fn has_unexpired_denial(&self, kind: Kind) -> bool {
        self.timed_kind_denials
            .get(&kind)
            .is_some_and(|&expiry| Timestamp::now().as_secs() < expiry)
    }

    /// Whether the app currently holds a live remember-grant: a Forever per-kind
    /// grant beyond the seeded `Reaction` default, or an unexpired non-NIP-98
    /// timed per-kind grant. A bare connection, or only the default `Reaction`
    /// (auto-approved globally regardless), does not count.
    ///
    /// This is the "still has something to remember" half of the persistence
    /// gate; combined with [`AppPermission::explicitly_remembered`] (the "user
    /// actually chose to remember, vs a client-supplied connect scope" half), it
    /// decides whether the app is persisted/restored. A merely-connected client
    /// must re-present the connect secret via a fresh `connect` after a bunker
    /// restart instead of being silently re-authorized, matching NIP-46's
    /// single-connection `secret` and the remember-only model of NIP-55.
    pub fn has_live_remember_grant(&self) -> bool {
        let now = now_unix_secs();
        self.auto_approve_kinds
            .iter()
            .any(|k| *k != Kind::Reaction && *k != NIP98_HTTP_AUTH)
            || self
                .timed_kind_grants
                .iter()
                .any(|(k, expiry)| *k != NIP98_HTTP_AUTH && now < *expiry)
    }

    /// Whether this app should be persisted / restored: the user explicitly
    /// remembered it AND it still holds a live remember-grant.
    pub fn is_persistable_remember(&self) -> bool {
        self.explicitly_remembered && self.has_live_remember_grant()
    }

    fn prune_expired_kind_grants(&mut self) {
        let now = now_unix_secs();
        self.timed_kind_grants.retain(|_, expiry| now < *expiry);
    }
}

fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // On clock error saturate to u64::MAX so timed-grant expiry checks
    // (`now < expiry`) read as expired (fail-closed) rather than eternal.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

pub struct PermissionManager {
    apps: HashMap<PublicKey, AppPermission>,
    global_auto_approve: HashSet<Kind>,
}

impl PermissionManager {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            global_auto_approve: HashSet::from([Kind::Reaction]),
        }
    }

    #[allow(dead_code)]
    pub fn grant(&mut self, pubkey: PublicKey, name: String, permissions: Permission) {
        let masked = permissions & Permission::ALL;
        if let Some(app) = self.apps.get_mut(&pubkey) {
            app.permissions |= masked;
            app.last_used = Timestamp::now();
        } else {
            let mut app = AppPermission::new(pubkey, name);
            app.permissions = masked;
            self.apps.insert(pubkey, app);
        }
    }

    pub const MAX_CONNECTED_APPS: usize = 100;

    fn evict_expired(&mut self) {
        self.apps
            .retain(|_, app| !app.duration.is_expired(app.connected_at));
    }

    pub fn ensure_capacity(&mut self, pubkey: &PublicKey) -> bool {
        if self.apps.len() < Self::MAX_CONNECTED_APPS || self.apps.contains_key(pubkey) {
            return true;
        }
        self.evict_expired();
        self.apps.len() < Self::MAX_CONNECTED_APPS
    }

    pub fn connect(&mut self, pubkey: PublicKey, name: String) -> bool {
        if !self.ensure_capacity(&pubkey) {
            return false;
        }
        self.apps
            .entry(pubkey)
            .or_insert_with(|| AppPermission::new(pubkey, name));
        true
    }

    pub fn connect_with_permissions(
        &mut self,
        pubkey: PublicKey,
        name: String,
        requested: Permission,
        auto_kinds: HashSet<Kind>,
    ) -> bool {
        if !self.ensure_capacity(&pubkey) {
            return false;
        }
        match self.apps.entry(pubkey) {
            Entry::Occupied(entry) => {
                let existing = entry.get().permissions;
                let masked = requested & Permission::ALL;
                if existing != masked {
                    let app_id = &pubkey.to_hex()[..8];
                    warn!(
                        app_id,
                        existing = ?existing,
                        requested = ?masked,
                        "reconnecting app requested different permissions; keeping existing"
                    );
                }
            }
            Entry::Vacant(entry) => {
                let mut app = AppPermission::new(pubkey, name);
                app.permissions = requested & Permission::ALL;
                // #575: NIP-98 (kind 27235) is never auto-approved.
                let mut auto_kinds = auto_kinds;
                auto_kinds.remove(&NIP98_HTTP_AUTH);
                if !auto_kinds.is_empty() {
                    app.auto_approve_kinds.extend(auto_kinds);
                }
                entry.insert(app);
            }
        }
        true
    }

    pub fn revoke(&mut self, pubkey: &PublicKey) {
        self.apps.remove(pubkey);
    }

    pub fn revoke_all(&mut self) {
        self.apps.clear();
    }

    pub fn revoke_session_apps(&mut self) {
        self.apps
            .retain(|_, app| !matches!(app.duration, PermissionDuration::Session));
    }

    pub fn has_permission(&self, pubkey: &PublicKey, perm: Permission) -> bool {
        self.apps
            .get(pubkey)
            .map(|app| {
                if app.duration.is_expired(app.connected_at) {
                    return false;
                }
                app.permissions.contains(perm)
            })
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_connected(&self, pubkey: &PublicKey) -> bool {
        self.apps.contains_key(pubkey)
    }

    /// Decide a request without prompting, or say that prompting is needed.
    ///
    /// A live refusal wins over a live grant. The two should not coexist, since
    /// recording either clears the other, but if they ever did, refusing is the
    /// answer that cannot authorise something the user did not intend.
    pub fn decide(&self, pubkey: &PublicKey, kind: Kind) -> ApprovalDecision {
        if let Some(app) = self.apps.get(pubkey) {
            if !app.duration.is_expired(app.connected_at) && app.has_unexpired_denial(kind) {
                return ApprovalDecision::Deny;
            }
        }
        if self.requires_prompt_ignoring_denials(pubkey, kind) {
            ApprovalDecision::Ask
        } else {
            ApprovalDecision::Allow
        }
    }

    /// Whether the caller must not proceed without further action.
    ///
    /// True for both a refusal and an unanswered request, because the only
    /// answer that permits proceeding silently is an explicit grant. Kept as a
    /// bool for the existing callers; prefer [`Self::decide`], which
    /// distinguishes the two and lets a refusal short-circuit the prompt.
    ///
    /// Deliberately not `decide(..) == Ask`. That reads better and is unsafe:
    /// it would return false for a refusal, so a caller writing
    /// `if !needs_approval { proceed }` would treat a remembered no as a yes.
    /// A signer must not have an API whose obvious misuse authorises signing.
    pub fn needs_approval(&self, pubkey: &PublicKey, kind: Kind) -> bool {
        self.decide(pubkey, kind) != ApprovalDecision::Allow
    }

    /// Record that the user refused `kind` for this app, for `secs`.
    ///
    /// Clears any grant for the same kind: a refusal that leaves an existing
    /// grant standing would be overridden by it the moment the decision is next
    /// taken, so the user's most recent answer has to be the one that holds.
    /// Returns whether anything was written, so callers only audit real changes.
    pub fn deny_kind_for(&mut self, pubkey: &PublicKey, kind: Kind, secs: u64) -> bool {
        if secs == 0 {
            return false;
        }
        let Some(app) = self.apps.get_mut(pubkey) else {
            return false;
        };
        // Clamp NIP-98 here rather than trusting the caller. The handler
        // already clamps its own path, but this is a public write API and the
        // invariant is that a refusal can never be remembered for longer than
        // an approval could; that has to hold at the point of writing.
        let secs = if kind == NIP98_HTTP_AUTH {
            secs.min(NIP98_MAX_REMEMBER_SECS)
        } else {
            secs
        };
        let expiry = Timestamp::now().as_secs().saturating_add(secs);
        app.auto_approve_kinds.remove(&kind);
        app.timed_kind_grants.remove(&kind);
        app.timed_kind_denials.insert(kind, expiry);
        true
    }

    /// Whether a prompt is required, considering grants only.
    ///
    /// Private because it answers half the question. A remembered refusal is
    /// resolved by [`Self::decide`], which consults this for the other half.
    fn requires_prompt_ignoring_denials(&self, pubkey: &PublicKey, kind: Kind) -> bool {
        // #613: NIP-98 (kind 27235) is opt-in remembered only via an explicit,
        // short, unexpired per-app timed grant written by the approval path. It
        // is never covered by a forever (auto_approve) or global grant: those
        // channels stay blocked here so a 27235 entry that slipped into a grant
        // set or a persisted/upgraded config cannot bypass the prompt. Only a
        // live, clamped timed grant skips it.
        //
        // Scope: the grant is keyed on (app pubkey, kind) only, so within the
        // clamped window it covers any url/method/relay. This matches Amber,
        // whose NIP-98 remember is also keyed on (app, kind) with no relay or
        // url/method scoping (it reserves relay scoping for NIP-42 relay auth,
        // kind 22242). Per-url scoping is intentionally not used: NIP-98 signs a
        // fresh `u` per request, so it would re-prompt on every API call and
        // defeat the fix. Keep is stricter than Amber on duration: Amber allows
        // a forever/one-week NIP-98 remember, while Keep hard-clamps it to
        // NIP98_MAX_REMEMBER_SECS. The bound is that short clamp plus the
        // client's existing NIP-46 authorization.
        if kind == NIP98_HTTP_AUTH {
            return !self.apps.get(pubkey).is_some_and(|app| {
                !app.duration.is_expired(app.connected_at) && app.has_unexpired_timed_grant(kind)
            });
        }
        if let Some(app) = self.apps.get(pubkey) {
            if !app.duration.is_expired(app.connected_at) {
                if app.auto_approve_kinds.contains(&kind) {
                    return false;
                }
                if app.has_unexpired_timed_grant(kind) {
                    return false;
                }
            }
        }
        if self.global_auto_approve.contains(&kind) {
            return false;
        }
        true
    }

    /// Persist a forever-grant for `kind` on the connected app at `pubkey`.
    /// No-op when the app is unknown. Used by the per-request approval prompt
    /// (#575) when the user picks `RememberDuration::Forever`. Returns whether a
    /// grant was actually written, so callers only audit real state changes.
    pub fn grant_kind_forever(&mut self, pubkey: &PublicKey, kind: Kind) -> bool {
        // #575: NIP-98 (kind 27235) is never remembered.
        if kind == NIP98_HTTP_AUTH {
            return false;
        }
        if let Some(app) = self.apps.get_mut(pubkey) {
            // Enforce the persisted-config cap (MAX_AUTO_KINDS) in memory so an
            // app cannot exceed what `RelayConfig` validation will later accept.
            if !app.auto_approve_kinds.contains(&kind)
                && app.auto_approve_kinds.len() >= MAX_AUTO_KINDS
            {
                return false;
            }
            app.auto_approve_kinds.insert(kind);
            // A Forever grant supersedes any timed grant for the same kind.
            app.timed_kind_grants.remove(&kind);
            // ...and any refusal. The decision path refuses ahead of allowing,
            // so a grant left sitting behind a live refusal would never take
            // effect and the user would see their approval ignored.
            app.timed_kind_denials.remove(&kind);
            app.last_used = Timestamp::now();
            // An explicit user remember-decision (vs a client-supplied connect
            // kind scope); gates cross-restart persistence.
            app.explicitly_remembered = true;
            return true;
        }
        false
    }

    /// Persist a timed grant for `kind` on the connected app at `pubkey` that
    /// expires `secs` seconds from now. No-op when the app is unknown or when
    /// `secs == 0`. Used by the per-request approval prompt (#575) when the
    /// user picks a `RememberDuration::OneMinute / FiveMinutes / TenMinutes /
    /// OneHour / OneDay` value. Returns whether a grant was actually written, so
    /// callers only audit real state changes.
    pub fn grant_kind_for(&mut self, pubkey: &PublicKey, kind: Kind, secs: u64) -> bool {
        if secs == 0 {
            return false;
        }
        // #613 defense-in-depth: NIP-98 (kind 27235) is a bearer-credential
        // grant, so its lifetime bound is enforced here at the authoritative
        // write path, not only in the approval-path clamp. Even if a future
        // caller forgets to clamp, the grant can never exceed the cap.
        let secs = if kind == NIP98_HTTP_AUTH {
            secs.min(NIP98_MAX_REMEMBER_SECS)
        } else {
            secs
        };
        let now = now_unix_secs();
        // Clock error reads as u64::MAX (fail-closed for expiry checks); refuse
        // to write a grant we could not bound, otherwise it would read as
        // eternal once the clock recovers.
        if now == u64::MAX {
            return false;
        }
        if let Some(app) = self.apps.get_mut(pubkey) {
            app.prune_expired_kind_grants();
            // A Forever grant already covers this kind; don't downgrade it.
            if app.auto_approve_kinds.contains(&kind) {
                return false;
            }
            // Enforce the persisted-config cap (MAX_AUTO_KINDS) in memory. A
            // re-approval of an already-granted kind is allowed (it replaces the
            // existing window) and does not count against the cap.
            if !app.timed_kind_grants.contains_key(&kind)
                && app.timed_kind_grants.len() >= MAX_AUTO_KINDS
            {
                return false;
            }
            // An explicit re-approval sets the new expiry, even if shorter, so
            // a user can deliberately shrink an over-granted window.
            let expiry = now.saturating_add(secs);
            app.timed_kind_grants.insert(kind, expiry);
            // Clear any refusal for the same kind. The decision path refuses
            // ahead of allowing, so a grant left behind a live refusal would
            // never take effect and the approval would appear to be ignored.
            app.timed_kind_denials.remove(&kind);
            app.last_used = Timestamp::now();
            // An explicit user remember-decision; gates cross-restart persistence.
            app.explicitly_remembered = true;
            return true;
        }
        false
    }

    pub fn record_usage(&mut self, pubkey: &PublicKey) {
        if let Some(app) = self.apps.get_mut(pubkey) {
            app.last_used = Timestamp::now();
            app.request_count += 1;
            // GC the app's expired per-kind timed grants on its request path.
            // `has_unexpired_timed_grant` / `needs_approval` only skip expired
            // entries without removing them, so without this they linger until
            // the app's next timed grant. Dropping an already-expired entry
            // never changes an authorization decision.
            app.prune_expired_kind_grants();
        }
    }

    pub fn get_app(&self, pubkey: &PublicKey) -> Option<&AppPermission> {
        self.apps.get(pubkey)
    }

    pub fn list_apps(&self) -> impl Iterator<Item = &AppPermission> {
        self.apps.values()
    }

    /// Serialize the current grants into the persisted `StoredBunkerPermission`
    /// form, the inverse of `restore_persisted`. Session apps are skipped (they
    /// are never persisted and `restore_persisted` would drop them anyway); each
    /// app's forever and timed per-kind grants are captured so a consumer can
    /// write a durable snapshot and reload it via `apply_pre_grants` on restart.
    pub fn stored_snapshot(&self) -> Vec<keep_core::relay::StoredBunkerPermission> {
        use keep_core::relay::{
            StoredBunkerPermission, StoredPermissionDuration, StoredTimedKindGrant,
        };
        let now = now_unix_secs();
        self.apps
            .values()
            .filter(|app| {
                !matches!(app.duration, PermissionDuration::Session)
                    && app.is_persistable_remember()
            })
            .map(|app| StoredBunkerPermission {
                pubkey_hex: app.pubkey.to_hex(),
                name: app.name.clone(),
                permissions: app.permissions.bits(),
                auto_approve_kinds: app.auto_approve_kinds.iter().map(|k| k.as_u16()).collect(),
                duration: match app.duration {
                    PermissionDuration::Session => StoredPermissionDuration::Session,
                    PermissionDuration::Seconds(s) => StoredPermissionDuration::Seconds(s),
                    PermissionDuration::Forever => StoredPermissionDuration::Forever,
                },
                connected_at: app.connected_at.as_secs(),
                timed_kind_grants: app
                    .timed_kind_grants
                    .iter()
                    .filter(|(kind, expiry)| **kind != NIP98_HTTP_AUTH && now < **expiry)
                    .map(|(k, expiry)| StoredTimedKindGrant {
                        kind: k.as_u16(),
                        expires_at: *expiry,
                    })
                    .collect(),
                explicitly_remembered: Some(app.explicitly_remembered),
            })
            .collect()
    }

    pub fn set_auto_approve_kinds(&mut self, kinds: HashSet<Kind>) {
        self.global_auto_approve = kinds;
    }

    pub fn set_permissions(&mut self, pubkey: &PublicKey, permissions: Permission) {
        if let Some(app) = self.apps.get_mut(pubkey) {
            app.permissions = permissions & Permission::ALL;
            app.last_used = Timestamp::now();
        }
    }

    pub fn set_duration(&mut self, pubkey: &PublicKey, duration: PermissionDuration) {
        if let Some(app) = self.apps.get_mut(pubkey) {
            app.duration = duration;
            if matches!(duration, PermissionDuration::Seconds(_)) {
                app.connected_at = Timestamp::now();
            }
            app.last_used = Timestamp::now();
        }
    }

    /// Restore an app from persisted state. Single source of truth for the
    /// Session-skip / expired-Seconds-skip / capacity-enforced insert path
    /// shared by `SignerHandler::restore_client` and the `apply_pre_grants`
    /// startup hook. Returns `true` if the app was inserted, `false` if it
    /// was skipped (Session, expired, or capacity full).
    #[allow(clippy::too_many_arguments)]
    pub fn restore_persisted(
        &mut self,
        pubkey: PublicKey,
        name: String,
        permissions: Permission,
        auto_kinds: HashSet<Kind>,
        duration: PermissionDuration,
        connected_at: Timestamp,
        timed_kind_grants: HashMap<Kind, u64>,
        explicitly_remembered: Option<bool>,
    ) -> bool {
        match duration {
            PermissionDuration::Session => return false,
            PermissionDuration::Seconds(_) if duration.is_expired(connected_at) => return false,
            _ => {}
        }
        if !self.ensure_capacity(&pubkey) {
            let app_id = &pubkey.to_hex()[..8];
            warn!(app_id, "restore_persisted: capacity full, skipping");
            return false;
        }
        let mut app = AppPermission::new(pubkey, name);
        app.permissions = permissions & Permission::ALL;
        // #575: drop any persisted NIP-98 (kind 27235) grant; it must never be
        // remembered, even if an older/upgraded config carried it.
        let mut auto_kinds = auto_kinds;
        auto_kinds.remove(&NIP98_HTTP_AUTH);
        app.auto_approve_kinds = auto_kinds;
        app.duration = duration;
        app.connected_at = connected_at;
        // Drop grants that expired while the bunker was down (a clock error
        // reads as u64::MAX so every grant prunes, fail-closed) and any NIP-98
        // grant that should never have been persisted.
        let now = now_unix_secs();
        app.timed_kind_grants = timed_kind_grants
            .into_iter()
            .filter(|(kind, expiry)| *kind != NIP98_HTTP_AUTH && now < *expiry)
            .collect();
        // Rebuild the remember flag. A legacy row (`None`) predates the flag, so
        // fall back to whether it still carries a live grant, which preserves a
        // genuine remembered app while dropping a legacy bare row. A current row
        // is authoritative, so a client that only supplied a connect-time kind
        // scope (persisted as `Some(false)`) is not resurrected.
        app.explicitly_remembered =
            explicitly_remembered.unwrap_or_else(|| app.has_live_remember_grant());
        // Only restore apps the user explicitly chose to remember AND that still
        // hold a live grant, so a merely-connected client must re-present the
        // connect secret via a fresh `connect` rather than being silently
        // re-authorized. Also migrates away pre-existing over-broad rows.
        if !app.is_persistable_remember() {
            return false;
        }
        self.insert(app);
        true
    }

    pub(crate) fn insert(&mut self, mut app: AppPermission) {
        app.permissions &= Permission::ALL;
        let key = app.pubkey;
        self.apps.insert(key, app);
    }

    pub fn set_auto_approve_kinds_for_app(&mut self, pubkey: &PublicKey, mut kinds: HashSet<Kind>) {
        // #575: NIP-98 (kind 27235) is never auto-approved.
        kinds.remove(&NIP98_HTTP_AUTH);
        if let Some(app) = self.apps.get_mut(pubkey) {
            // Clear refusals for the kinds being granted. This is the only
            // grant path that does not come from a prompt, and once a refusal
            // stands the prompt never fires, so without this there is no route
            // from refused back to allowed short of waiting out the window,
            // restarting, or revoking the app: the broad answer this feature
            // exists to avoid.
            for kind in &kinds {
                app.timed_kind_denials.remove(kind);
            }
            // A user configuring auto-approve kinds is an explicit remember
            // decision, so gate persistence keeps it (and does not false-drop it
            // on restart). Clearing to empty leaves the flag untouched so a
            // separate live timed grant still counts as remembered.
            if !kinds.is_empty() {
                app.explicitly_remembered = true;
            }
            app.auto_approve_kinds = kinds;
            app.last_used = Timestamp::now();
        }
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip44_v3_flags_resolve_and_are_in_all() {
        assert_eq!(
            Permission::from_canonical_name("nip44v3_encrypt"),
            Some(Permission::NIP44_V3_ENCRYPT)
        );
        assert_eq!(
            Permission::from_canonical_name("nip44v3_decrypt"),
            Some(Permission::NIP44_V3_DECRYPT)
        );
        assert!(Permission::ALL.contains(Permission::NIP44_V3_ENCRYPT));
        assert!(Permission::ALL.contains(Permission::NIP44_V3_DECRYPT));
        // Round-trips through the name table.
        assert_eq!(
            Permission::NIP44_V3_ENCRYPT.to_names(),
            "nip44v3_encrypt".to_string()
        );
    }

    #[test]
    fn test_permission_manager() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();

        assert!(!pm.is_connected(&pubkey));

        pm.connect(pubkey, "Test App".into());
        assert!(pm.is_connected(&pubkey));
        assert!(pm.has_permission(&pubkey, Permission::GET_PUBLIC_KEY));
        assert!(!pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        pm.grant(pubkey, "Test App".into(), Permission::SIGN_EVENT);
        assert!(pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        assert!(!pm.needs_approval(&pubkey, Kind::Reaction));
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));

        pm.revoke(&pubkey);
        assert!(!pm.is_connected(&pubkey));
    }

    #[test]
    fn record_usage_gcs_expired_timed_grants() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // Inject an already-expired timed grant directly (the write path always
        // sets a future expiry, so simulate a grant whose window has passed).
        let past = now_unix_secs().saturating_sub(100);
        pm.apps
            .get_mut(&pubkey)
            .unwrap()
            .timed_kind_grants
            .insert(Kind::from(9999u16), past);

        // The read path already treats it as expired...
        assert!(pm.needs_approval(&pubkey, Kind::from(9999u16)));
        // ...and the next request through record_usage garbage-collects it.
        pm.record_usage(&pubkey);
        assert!(
            pm.apps.get(&pubkey).unwrap().timed_kind_grants.is_empty(),
            "expired timed grant must be garbage-collected on the request path"
        );
    }

    #[test]
    fn test_connect_with_permissions() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();

        assert!(pm.connect_with_permissions(
            pubkey,
            "Test App".into(),
            Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            HashSet::new(),
        ));
        assert!(pm.is_connected(&pubkey));
        assert!(pm.has_permission(&pubkey, Permission::SIGN_EVENT));
        assert!(!pm.has_permission(&pubkey, Permission::NIP44_ENCRYPT));
    }

    #[test]
    fn test_max_connected_apps() {
        let mut pm = PermissionManager::new();
        for _ in 0..PermissionManager::MAX_CONNECTED_APPS {
            let pubkey = Keys::generate().public_key();
            pm.connect(pubkey, "App".into());
        }
        assert_eq!(pm.apps.len(), PermissionManager::MAX_CONNECTED_APPS);

        let extra = Keys::generate().public_key();
        pm.connect(extra, "Extra".into());
        assert!(!pm.is_connected(&extra));
    }

    #[test]
    fn test_permission_duration_expiry() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();

        pm.connect(pubkey, "Test".into());
        pm.grant(pubkey, "Test".into(), Permission::SIGN_EVENT);
        assert!(pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.duration = PermissionDuration::Seconds(0);
            app.connected_at = Timestamp::from(1);
        }
        assert!(!pm.has_permission(&pubkey, Permission::SIGN_EVENT));
        assert!(!pm.needs_approval(&pubkey, Kind::Reaction));
    }

    #[test]
    fn test_permission_duration_forever() {
        assert!(!PermissionDuration::Forever.is_expired(Timestamp::from(1)));
    }

    #[test]
    fn test_permission_duration_session() {
        assert!(!PermissionDuration::Session.is_expired(Timestamp::from(1)));
    }

    #[test]
    fn test_set_permissions() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "Test".into());

        assert!(pm.has_permission(&pubkey, Permission::GET_PUBLIC_KEY));
        assert!(!pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        pm.set_permissions(&pubkey, Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT);
        assert!(pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        pm.set_permissions(&pubkey, Permission::GET_PUBLIC_KEY);
        assert!(!pm.has_permission(&pubkey, Permission::SIGN_EVENT));
    }

    #[test]
    fn test_set_duration() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "Test".into());

        let app = pm.get_app(&pubkey).unwrap();
        assert!(matches!(app.duration, PermissionDuration::Forever));

        pm.set_duration(&pubkey, PermissionDuration::Seconds(3600));
        let app = pm.get_app(&pubkey).unwrap();
        assert!(matches!(app.duration, PermissionDuration::Seconds(3600)));
    }

    #[test]
    fn test_set_auto_approve_kinds_for_app() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "Test".into());
        pm.grant(pubkey, "Test".into(), Permission::SIGN_EVENT);

        assert!(pm.needs_approval(&pubkey, Kind::TextNote));

        pm.set_auto_approve_kinds_for_app(&pubkey, HashSet::from([Kind::TextNote, Kind::Reaction]));
        assert!(!pm.needs_approval(&pubkey, Kind::TextNote));
        assert!(!pm.needs_approval(&pubkey, Kind::Reaction));
        assert!(pm.needs_approval(&pubkey, Kind::from(30023)));
    }

    #[test]
    fn test_connect_with_auto_kinds() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect_with_permissions(
            pubkey,
            "Test".into(),
            Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            HashSet::from([Kind::TextNote]),
        );

        assert!(!pm.needs_approval(&pubkey, Kind::TextNote));
        assert!(pm.needs_approval(&pubkey, Kind::from(30023)));
    }

    #[test]
    fn test_set_global_auto_approve_kinds() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "Test".into());
        pm.grant(pubkey, "Test".into(), Permission::SIGN_EVENT);

        // No per-app auto-kinds, so the app needs approval for TextNote.
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));

        // A global list skips approval regardless of any per-app config.
        pm.set_auto_approve_kinds(HashSet::from([Kind::TextNote]));
        assert!(!pm.needs_approval(&pubkey, Kind::TextNote));
        assert!(pm.needs_approval(&pubkey, Kind::from(30023)));

        // Replacing the global list with an empty set restores approval.
        pm.set_auto_approve_kinds(HashSet::new());
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));
    }

    #[test]
    fn timed_grant_skips_approval_until_pruned() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // No grant yet: approval required.
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));

        // A non-zero timed grant is honored.
        pm.grant_kind_for(&pubkey, Kind::TextNote, 60);
        assert!(!pm.needs_approval(&pubkey, Kind::TextNote));

        // Force the grant to expire: needs_approval skips the expired entry and
        // returns true again. The stale entry stays in the map until the next
        // mutation prunes it; the read path does not remove it.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants.insert(Kind::TextNote, 1);
        }
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));
    }

    #[test]
    fn forever_grant_is_not_downgraded_by_timed_grant() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_forever(&pubkey, Kind::TextNote);
        pm.grant_kind_for(&pubkey, Kind::TextNote, 60);

        let app = pm.get_app(&pubkey).unwrap();
        assert!(app.auto_approve_kinds.contains(&Kind::TextNote));
        assert!(!app.timed_kind_grants.contains_key(&Kind::TextNote));
    }

    #[test]
    fn forever_grant_removes_pre_existing_timed_grant() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_for(&pubkey, Kind::TextNote, 60);
        pm.grant_kind_forever(&pubkey, Kind::TextNote);

        let app = pm.get_app(&pubkey).unwrap();
        assert!(app.auto_approve_kinds.contains(&Kind::TextNote));
        assert!(!app.timed_kind_grants.contains_key(&Kind::TextNote));
    }

    #[test]
    fn timed_grant_replaces_window_on_reapproval() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_for(&pubkey, Kind::TextNote, 24 * 60 * 60);
        let before = pm.get_app(&pubkey).unwrap().timed_kind_grants[&Kind::TextNote];

        // An explicit re-approval with a shorter window replaces the existing
        // expiry so a user can deliberately shrink an over-granted window.
        pm.grant_kind_for(&pubkey, Kind::TextNote, 60);
        let after = pm.get_app(&pubkey).unwrap().timed_kind_grants[&Kind::TextNote];
        assert!(after < before);
    }

    #[test]
    fn restore_persisted_keeps_future_grant_prunes_expired() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let now = now_unix_secs();
        let expired_kind = Kind::Custom(30023);
        let mut grants = HashMap::new();
        grants.insert(Kind::TextNote, now + 3600);
        grants.insert(expired_kind, 1);

        let restored = pm.restore_persisted(
            pubkey,
            "App".into(),
            Permission::SIGN_EVENT,
            HashSet::new(),
            PermissionDuration::Forever,
            Timestamp::now(),
            grants,
            None,
        );
        assert!(restored);

        // Future-dated grant survives the restart; the expired one is pruned.
        assert!(!pm.needs_approval(&pubkey, Kind::TextNote));
        assert!(pm.needs_approval(&pubkey, expired_kind));
        assert!(!pm
            .get_app(&pubkey)
            .unwrap()
            .timed_kind_grants
            .contains_key(&expired_kind));
    }

    #[test]
    fn nip98_skipped_only_by_explicit_timed_grant() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // #613: a forever (auto_approve) or global grant must NOT bypass NIP-98,
        // even when forced directly into the sets past the write-path guards.
        pm.set_auto_approve_kinds(HashSet::from([NIP98_HTTP_AUTH]));
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.auto_approve_kinds.insert(NIP98_HTTP_AUTH);
        }
        assert!(
            pm.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "NIP-98 must still prompt when only forever/global grants cover it"
        );

        // Only an explicit, unexpired per-app timed grant skips the prompt.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants
                .insert(NIP98_HTTP_AUTH, now_unix_secs() + 600);
        }
        assert!(
            !pm.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "an explicit unexpired NIP-98 timed grant skips the prompt"
        );
    }

    #[test]
    fn nip98_timed_grant_does_not_outlive_app_duration() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants
                .insert(NIP98_HTTP_AUTH, now_unix_secs() + 600);
        }
        assert!(
            !pm.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "a live NIP-98 timed grant skips the prompt while the app duration holds"
        );

        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.duration = PermissionDuration::Seconds(0);
            app.connected_at = Timestamp::from(1);
        }
        assert!(
            pm.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "an expired app duration must override a live NIP-98 timed grant"
        );
    }

    #[test]
    fn nip98_re_prompts_after_grant_own_expiry() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // A grant whose own expiry is already in the past must re-prompt, even
        // while the app duration still holds.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants
                .insert(NIP98_HTTP_AUTH, now_unix_secs() - 1);
        }
        assert!(
            pm.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "an expired NIP-98 timed grant must re-prompt"
        );
    }

    #[test]
    fn grant_kind_for_caps_nip98_lifetime() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // Defense-in-depth: an over-long NIP-98 grant request is capped to the
        // max at the write path, independent of the approval-path clamp.
        let before = now_unix_secs();
        assert!(pm.grant_kind_for(&pubkey, NIP98_HTTP_AUTH, 24 * 60 * 60));
        let expiry = *pm
            .get_app(&pubkey)
            .unwrap()
            .timed_kind_grants
            .get(&NIP98_HTTP_AUTH)
            .unwrap();
        assert!(
            expiry <= before.saturating_add(NIP98_MAX_REMEMBER_SECS) + 1,
            "NIP-98 grant lifetime must be capped to NIP98_MAX_REMEMBER_SECS"
        );
    }

    #[test]
    fn stored_snapshot_never_emits_nip98_timed_grant() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_for(&pubkey, Kind::TextNote, 3600);
        // Inject a NIP-98 timed grant directly past the write-path cap to prove
        // the save filter is an independent layer.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants
                .insert(NIP98_HTTP_AUTH, now_unix_secs() + 600);
        }
        let snapshot = pm.stored_snapshot();
        let app = snapshot
            .iter()
            .find(|p| p.pubkey_hex == pubkey.to_hex())
            .unwrap();
        assert!(
            app.timed_kind_grants
                .iter()
                .all(|g| g.kind != NIP98_HTTP_AUTH.as_u16()),
            "stored_snapshot must never persist a NIP-98 timed grant"
        );
        assert!(app
            .timed_kind_grants
            .iter()
            .any(|g| g.kind == Kind::TextNote.as_u16()));
    }

    #[test]
    fn restore_persisted_strips_nip98_grants() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let now = now_unix_secs();

        let mut grants = HashMap::new();
        grants.insert(NIP98_HTTP_AUTH, now + 3600);
        grants.insert(Kind::TextNote, now + 3600);

        let restored = pm.restore_persisted(
            pubkey,
            "App".into(),
            Permission::SIGN_EVENT,
            HashSet::from([NIP98_HTTP_AUTH, Kind::Reaction]),
            PermissionDuration::Forever,
            Timestamp::now(),
            grants,
            None,
        );
        assert!(restored);

        let app = pm.get_app(&pubkey).unwrap();
        assert!(!app.auto_approve_kinds.contains(&NIP98_HTTP_AUTH));
        assert!(!app.timed_kind_grants.contains_key(&NIP98_HTTP_AUTH));
        // Non-NIP-98 grants survive the restore.
        assert!(app.auto_approve_kinds.contains(&Kind::Reaction));
        assert!(app.timed_kind_grants.contains_key(&Kind::TextNote));
        assert!(pm.needs_approval(&pubkey, NIP98_HTTP_AUTH));
    }

    #[test]
    fn timed_grant_round_trips_but_nip98_does_not() {
        // Create a non-NIP-98 timed grant, capture it as the persistence layer
        // would, restore it, and confirm it survives; a 27235 grant captured the
        // same way must not survive the restore.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_for(&pubkey, Kind::TextNote, 3600);
        // Inject a NIP-98 timed grant directly to model a hostile/legacy
        // persisted row; restore must drop it regardless of how it got there.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_grants
                .insert(NIP98_HTTP_AUTH, now_unix_secs() + 3600);
        }
        let persisted = pm.get_app(&pubkey).unwrap().timed_kind_grants.clone();

        let mut restored = PermissionManager::new();
        restored.restore_persisted(
            pubkey,
            "App".into(),
            Permission::SIGN_EVENT,
            HashSet::new(),
            PermissionDuration::Forever,
            Timestamp::now(),
            persisted,
            None,
        );

        assert!(
            !restored.needs_approval(&pubkey, Kind::TextNote),
            "non-NIP-98 timed grant must survive the round trip"
        );
        assert!(
            restored.needs_approval(&pubkey, NIP98_HTTP_AUTH),
            "NIP-98 must not survive the round trip"
        );
    }

    #[test]
    fn stored_snapshot_round_trips_through_restore() {
        // The mobile bunker persists grants by serializing `stored_snapshot()`
        // and reloads them via `restore_persisted` on the next start. Prove that
        // a forever grant and a timed grant survive that exact round trip.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());
        assert!(pm.grant_kind_forever(&pubkey, Kind::TextNote));
        assert!(pm.grant_kind_for(&pubkey, Kind::Custom(30023), 3600));

        let snapshot = pm.stored_snapshot();
        assert_eq!(snapshot.len(), 1, "one connected app is serialized");
        let stored = &snapshot[0];
        assert_eq!(stored.pubkey_hex, pubkey.to_hex());
        assert!(stored.auto_approve_kinds.contains(&Kind::TextNote.as_u16()));
        assert!(stored
            .timed_kind_grants
            .iter()
            .any(|g| g.kind == Kind::Custom(30023).as_u16()));

        let auto: HashSet<Kind> = stored
            .auto_approve_kinds
            .iter()
            .copied()
            .map(Kind::from)
            .collect();
        let timed: HashMap<Kind, u64> = stored
            .timed_kind_grants
            .iter()
            .map(|g| (Kind::from(g.kind), g.expires_at))
            .collect();
        let duration = match &stored.duration {
            keep_core::relay::StoredPermissionDuration::Session => PermissionDuration::Session,
            keep_core::relay::StoredPermissionDuration::Seconds(s) => {
                PermissionDuration::Seconds(*s)
            }
            keep_core::relay::StoredPermissionDuration::Forever => PermissionDuration::Forever,
        };
        let mut restored = PermissionManager::new();
        restored.restore_persisted(
            pubkey,
            stored.name.clone(),
            Permission::from_bits_truncate(stored.permissions),
            auto,
            duration,
            Timestamp::from_secs(stored.connected_at),
            timed,
            stored.explicitly_remembered,
        );

        assert!(
            !restored.needs_approval(&pubkey, Kind::TextNote),
            "forever grant survives the snapshot/restore round trip"
        );
        assert!(
            !restored.needs_approval(&pubkey, Kind::Custom(30023)),
            "timed grant survives the snapshot/restore round trip"
        );
        assert!(
            restored.needs_approval(&pubkey, Kind::Metadata),
            "an ungranted kind still prompts after restore"
        );
    }

    #[test]
    fn stored_snapshot_omits_bare_connected_app() {
        // A merely-connected app (secret accepted, SIGN_EVENT capability, but no
        // remember-decision) must NOT be persisted, or it would be silently
        // re-authorized on the next start without re-presenting the secret.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect_with_permissions(
            pubkey,
            "App".into(),
            Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            HashSet::new(),
        );
        assert!(
            pm.stored_snapshot().is_empty(),
            "a connected app with no remember-grant is not persisted"
        );
    }

    #[test]
    fn stored_snapshot_reaction_only_is_treated_as_bare() {
        // Reaction (kind 7) is the seeded default and is auto-approved globally,
        // so an app carrying only Reaction is indistinguishable from a bare
        // connection and must not be persisted.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());
        assert!(pm.grant_kind_forever(&pubkey, Kind::Reaction));
        assert!(
            pm.stored_snapshot().is_empty(),
            "a Reaction-only app is not persisted"
        );
    }

    #[test]
    fn stored_snapshot_keeps_forever_and_timed_remembers() {
        let mut pm = PermissionManager::new();
        let forever = Keys::generate().public_key();
        let timed = Keys::generate().public_key();
        let bare = Keys::generate().public_key();
        pm.connect(forever, "Forever".into());
        pm.connect(timed, "Timed".into());
        pm.connect(bare, "Bare".into());
        assert!(pm.grant_kind_forever(&forever, Kind::TextNote));
        assert!(pm.grant_kind_for(&timed, Kind::TextNote, 3600));

        let snapshot = pm.stored_snapshot();
        assert_eq!(snapshot.len(), 2, "only the two remembered apps persist");
        let hexes: HashSet<String> = snapshot.iter().map(|s| s.pubkey_hex.clone()).collect();
        assert!(hexes.contains(&forever.to_hex()));
        assert!(hexes.contains(&timed.to_hex()));
        assert!(!hexes.contains(&bare.to_hex()));
    }

    #[test]
    fn restore_persisted_drops_legacy_bare_row() {
        // A legacy over-captured row (SIGN_EVENT, only the Reaction seed, no timed
        // grant) is dropped on restore, migrating away the old broad persistence.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let restored = pm.restore_persisted(
            pubkey,
            "Bare".into(),
            Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            HashSet::from([Kind::Reaction]),
            PermissionDuration::Forever,
            Timestamp::now(),
            HashMap::new(),
            None,
        );
        assert!(!restored, "a bare legacy row is not restored");
        assert!(pm.get_app(&pubkey).is_none());
    }

    #[test]
    fn restore_persisted_drops_expired_timed_only_row() {
        // A row whose only grant is a timed grant that expired while the bunker
        // was down prunes to empty, leaving no remember, so it is dropped.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let mut grants = HashMap::new();
        grants.insert(Kind::TextNote, 1); // expiry at epoch+1s: always in the past
        let restored = pm.restore_persisted(
            pubkey,
            "Expired".into(),
            Permission::SIGN_EVENT,
            HashSet::new(),
            PermissionDuration::Forever,
            Timestamp::now(),
            grants,
            None,
        );
        assert!(
            !restored,
            "an app whose only grant expired while down is dropped"
        );
        assert!(pm.get_app(&pubkey).is_none());
    }

    #[test]
    fn restore_persisted_drops_nip98_only_row() {
        // A legacy row whose only grants are NIP-98 (stripped on restore) leaves
        // no remember and is dropped rather than silently re-authorized.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let mut grants = HashMap::new();
        grants.insert(NIP98_HTTP_AUTH, now_unix_secs() + 3600);
        let restored = pm.restore_persisted(
            pubkey,
            "Nip98".into(),
            Permission::SIGN_EVENT,
            HashSet::from([NIP98_HTTP_AUTH]),
            PermissionDuration::Forever,
            Timestamp::now(),
            grants,
            None,
        );
        assert!(!restored, "a NIP-98-only legacy row is dropped on restore");
        assert!(pm.get_app(&pubkey).is_none());
    }

    #[test]
    fn stored_snapshot_omits_client_scoped_connect() {
        // A client that requests a kind-scoped signing permission at connect
        // (`sign_event:1` -> auto-approve kind 1) is silently approved for that
        // kind this session, but must NOT self-qualify for cross-restart
        // persistence: only an explicit user remember does.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect_with_permissions(
            pubkey,
            "App".into(),
            Permission::GET_PUBLIC_KEY | Permission::SIGN_EVENT,
            HashSet::from([Kind::Custom(1)]),
        );
        assert!(
            !pm.needs_approval(&pubkey, Kind::Custom(1)),
            "client scope is live"
        );
        assert!(
            pm.stored_snapshot().is_empty(),
            "a client-supplied connect kind scope is not persisted"
        );
        // Once the user explicitly remembers a kind, the app persists.
        assert!(pm.grant_kind_forever(&pubkey, Kind::Custom(2)));
        assert_eq!(pm.stored_snapshot().len(), 1);
    }

    #[test]
    fn restore_persisted_drops_row_marked_not_remembered() {
        // A row authoritatively flagged not-remembered (`Some(false)`, e.g. a
        // client connect scope persisted under an older path) is not restored,
        // even though it carries a non-Reaction auto kind.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        let restored = pm.restore_persisted(
            pubkey,
            "Client".into(),
            Permission::SIGN_EVENT,
            HashSet::from([Kind::Custom(1)]),
            PermissionDuration::Forever,
            Timestamp::now(),
            HashMap::new(),
            Some(false),
        );
        assert!(!restored, "a row marked not-remembered is not restored");
        assert!(pm.get_app(&pubkey).is_none());
    }

    #[test]
    fn set_auto_approve_kinds_marks_app_remembered() {
        // A user configuring auto-approve kinds is an explicit remember, so the
        // app persists (and is not false-dropped by the gated persist path).
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());
        assert!(!pm.get_app(&pubkey).unwrap().explicitly_remembered);
        assert!(pm.stored_snapshot().is_empty());

        pm.set_auto_approve_kinds_for_app(&pubkey, HashSet::from([Kind::TextNote]));
        assert!(pm.get_app(&pubkey).unwrap().explicitly_remembered);
        assert_eq!(pm.stored_snapshot().len(), 1);
    }

    #[test]
    fn set_auto_approve_kinds_empty_preserves_timed_remember() {
        // Clearing auto-approve kinds must not un-remember an app that still holds
        // a live timed grant (a separate explicit remember decision).
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());
        assert!(pm.grant_kind_for(&pubkey, Kind::TextNote, 3600));
        assert!(pm.get_app(&pubkey).unwrap().explicitly_remembered);

        pm.set_auto_approve_kinds_for_app(&pubkey, HashSet::new());
        assert!(
            pm.get_app(&pubkey).unwrap().explicitly_remembered,
            "clearing auto-kinds must not drop a live timed remember"
        );
        assert_eq!(pm.stored_snapshot().len(), 1);
    }

    #[test]
    fn grant_kind_forever_enforces_max_auto_kinds_cap() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        // Fill auto_approve_kinds up to the cap with distinct custom kinds.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.auto_approve_kinds.clear();
            for k in 0..MAX_AUTO_KINDS as u16 {
                app.auto_approve_kinds.insert(Kind::Custom(k));
            }
        }
        assert_eq!(
            pm.get_app(&pubkey).unwrap().auto_approve_kinds.len(),
            MAX_AUTO_KINDS
        );

        // A new kind is refused once at the cap.
        assert!(!pm.grant_kind_forever(&pubkey, Kind::Custom(60000)));
        // Re-granting an already-present kind still succeeds.
        assert!(pm.grant_kind_forever(&pubkey, Kind::Custom(0)));
    }

    #[test]
    fn grant_kind_for_enforces_max_auto_kinds_cap() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        let now = now_unix_secs();
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            for k in 0..MAX_AUTO_KINDS as u16 {
                app.timed_kind_grants.insert(Kind::Custom(k), now + 3600);
            }
        }

        // A new kind is refused once at the cap.
        assert!(!pm.grant_kind_for(&pubkey, Kind::Custom(60000), 3600));
        // Re-granting an already-present kind replaces its window, still ok.
        assert!(pm.grant_kind_for(&pubkey, Kind::Custom(0), 60));
    }

    #[test]
    fn grant_kind_for_zero_seconds_is_noop() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "App".into());

        pm.grant_kind_for(&pubkey, Kind::TextNote, 0);
        assert!(!pm
            .get_app(&pubkey)
            .unwrap()
            .timed_kind_grants
            .contains_key(&Kind::TextNote));
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));
    }

    #[test]
    fn a_refusal_decides_the_next_request_without_prompting() {
        // The point of the change. Before it, a refusal decided one request:
        // the next identical one prompted again, so a client that retries
        // turned one "no" into an unbounded stream of prompts.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        assert_eq!(
            pm.decide(&pubkey, Kind::TextNote),
            ApprovalDecision::Ask,
            "nothing on record yet, so it must ask"
        );

        assert!(pm.deny_kind_for(&pubkey, Kind::TextNote, 3600));

        assert_eq!(
            pm.decide(&pubkey, Kind::TextNote),
            ApprovalDecision::Deny,
            "the refusal must hold without prompting again"
        );
        // Scoped to the kind that was refused, not the app. Uses a kind that
        // genuinely asks: Reaction is auto-approved by default here, so it
        // would have read as Allow and proven nothing about scoping.
        assert_eq!(
            pm.decide(&pubkey, Kind::from(9999u16)),
            ApprovalDecision::Ask,
            "refusing one kind must not silently refuse the others"
        );
    }

    #[test]
    fn an_expired_refusal_asks_again() {
        // A refusal is a pause, not a revocation. If it never expired it would
        // be a permanent block wearing a duration, and the user would have no
        // way back other than revoking the app.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        assert!(pm.deny_kind_for(&pubkey, Kind::TextNote, 1));
        // Rewind the recorded expiry rather than sleeping.
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            app.timed_kind_denials.insert(Kind::TextNote, 1);
        }
        assert_eq!(
            pm.decide(&pubkey, Kind::TextNote),
            ApprovalDecision::Ask,
            "an elapsed refusal must stop applying"
        );
    }

    #[test]
    fn approving_clears_a_standing_refusal() {
        // The decision path refuses ahead of allowing, so a grant written while
        // a refusal still stood would never take effect: the user would approve
        // and watch nothing change.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        assert!(pm.deny_kind_for(&pubkey, Kind::TextNote, 3600));
        assert_eq!(pm.decide(&pubkey, Kind::TextNote), ApprovalDecision::Deny);

        assert!(pm.grant_kind_for(&pubkey, Kind::TextNote, 3600));
        assert_eq!(
            pm.decide(&pubkey, Kind::TextNote),
            ApprovalDecision::Allow,
            "an explicit approval must override the earlier refusal"
        );

        // And the same via a forever grant.
        assert!(pm.deny_kind_for(&pubkey, Kind::Reaction, 3600));
        assert!(pm.grant_kind_forever(&pubkey, Kind::Reaction));
        assert_eq!(pm.decide(&pubkey, Kind::Reaction), ApprovalDecision::Allow);
    }

    #[test]
    fn a_refusal_wins_over_a_grant_if_both_somehow_stand() {
        // They should not coexist, since recording either clears the other.
        // This pins the tie-break anyway: for a signer the answer that cannot
        // authorise something unintended is the safe one.
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        assert!(pm.grant_kind_for(&pubkey, Kind::TextNote, 3600));
        if let Some(app) = pm.apps.get_mut(&pubkey) {
            let expiry = Timestamp::now().as_secs() + 3600;
            app.timed_kind_denials.insert(Kind::TextNote, expiry);
        }
        assert_eq!(
            pm.decide(&pubkey, Kind::TextNote),
            ApprovalDecision::Deny,
            "refusal must win the tie"
        );
    }

    /// The boolean API must not report "no approval needed" for a refusal.
    ///
    /// This is the one way remembering a refusal could make things worse than
    /// not remembering it. A caller writing `if !needs_approval { proceed }` is
    /// the obvious use of a boolean, so the boolean has to be false only when
    /// proceeding is actually permitted.
    #[test]
    fn needs_approval_never_reports_a_refusal_as_permission_to_proceed() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        // Granted, so proceeding is permitted and the bool is false.
        assert!(pm.grant_kind_for(&pubkey, Kind::from(9999u16), 3600));
        assert!(!pm.needs_approval(&pubkey, Kind::from(9999u16)));

        // Refused. The bool must go back to true: a refusal is not permission.
        assert!(pm.deny_kind_for(&pubkey, Kind::from(9999u16), 3600));
        assert_eq!(
            pm.decide(&pubkey, Kind::from(9999u16)),
            ApprovalDecision::Deny
        );
        assert!(
            pm.needs_approval(&pubkey, Kind::from(9999u16)),
            "a remembered refusal must never read as permission to proceed"
        );
    }

    /// A refusal cannot be remembered for longer than an approval could.
    #[test]
    fn a_nip98_refusal_is_clamped_like_a_nip98_approval() {
        let mut pm = PermissionManager::new();
        let pubkey = Keys::generate().public_key();
        pm.connect(pubkey, "agent".into());

        let before = Timestamp::now().as_secs();
        assert!(pm.deny_kind_for(&pubkey, NIP98_HTTP_AUTH, 30 * 24 * 3600));

        let expiry = *pm
            .apps
            .get(&pubkey)
            .expect("app")
            .timed_kind_denials
            .get(&NIP98_HTTP_AUTH)
            .expect("denial recorded");
        assert!(
            expiry <= before + NIP98_MAX_REMEMBER_SECS + 2,
            "a month-long NIP-98 refusal must be clamped to the same window an approval gets"
        );
    }
}
