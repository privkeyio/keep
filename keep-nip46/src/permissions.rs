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

        const DEFAULT = Self::GET_PUBLIC_KEY.bits();

        const ALL = Self::GET_PUBLIC_KEY.bits()
                  | Self::SIGN_EVENT.bits()
                  | Self::NIP04_ENCRYPT.bits()
                  | Self::NIP04_DECRYPT.bits()
                  | Self::NIP44_ENCRYPT.bits()
                  | Self::NIP44_DECRYPT.bits();
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
    pub connected_at: Timestamp,
    pub last_used: Timestamp,
    pub request_count: u64,
    #[serde(default = "default_duration")]
    pub duration: PermissionDuration,
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
            connected_at: Timestamp::now(),
            last_used: Timestamp::now(),
            request_count: 0,
            duration: PermissionDuration::Forever,
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

    /// Whether the user has made an explicit remember-decision for this app: a
    /// Forever per-kind grant beyond the seeded `Reaction` default, or a live
    /// non-NIP-98 timed per-kind grant. A bare connection, or only the default
    /// `Reaction` (which is auto-approved globally regardless), does not count.
    ///
    /// Only such apps are persisted and restored, so a merely-connected client
    /// must re-present the connect secret via a fresh `connect` after a bunker
    /// restart instead of being silently re-authorized. This matches NIP-46's
    /// single-connection `secret` and the remember-only persistence model used
    /// by NIP-55 and reference signers.
    pub fn has_explicit_remember_grant(&self) -> bool {
        let now = now_unix_secs();
        self.auto_approve_kinds
            .iter()
            .any(|k| *k != Kind::Reaction && *k != NIP98_HTTP_AUTH)
            || self
                .timed_kind_grants
                .iter()
                .any(|(k, expiry)| *k != NIP98_HTTP_AUTH && now < *expiry)
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

    pub fn needs_approval(&self, pubkey: &PublicKey, kind: Kind) -> bool {
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
            app.last_used = Timestamp::now();
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
            app.last_used = Timestamp::now();
            return true;
        }
        false
    }

    pub fn record_usage(&mut self, pubkey: &PublicKey) {
        if let Some(app) = self.apps.get_mut(pubkey) {
            app.last_used = Timestamp::now();
            app.request_count += 1;
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
                    && app.has_explicit_remember_grant()
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
        // Only restore apps the user explicitly chose to remember. A record with
        // no remaining remember-grant (a bare connection, or a legacy row that
        // over-captured every connected app) is dropped so the client must
        // re-present the connect secret via a fresh `connect` rather than being
        // silently re-authorized; this also migrates away pre-existing over-broad
        // rows on the next load.
        if !app.has_explicit_remember_grant() {
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
        );
        assert!(!restored, "a NIP-98-only legacy row is dropped on restore");
        assert!(pm.get_app(&pubkey).is_none());
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
}
