// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::warn;

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
    /// prompt (#575). Skipped on read once `now() >= expiry`. Intentionally
    /// process-lifetime only: `#[serde(skip)]` because the restore path does
    /// not carry timed grants, so they must not appear to survive a restart.
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
            .map(|expiry| now_unix_secs() < *expiry)
            .unwrap_or(false)
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
        if let Some(app) = self.apps.get_mut(pubkey) {
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
    pub fn restore_persisted(
        &mut self,
        pubkey: PublicKey,
        name: String,
        permissions: Permission,
        auto_kinds: HashSet<Kind>,
        duration: PermissionDuration,
        connected_at: Timestamp,
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
        app.auto_approve_kinds = auto_kinds;
        app.duration = duration;
        app.connected_at = connected_at;
        self.insert(app);
        true
    }

    pub(crate) fn insert(&mut self, mut app: AppPermission) {
        app.permissions &= Permission::ALL;
        let key = app.pubkey;
        self.apps.insert(key, app);
    }

    pub fn set_auto_approve_kinds_for_app(&mut self, pubkey: &PublicKey, kinds: HashSet<Kind>) {
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
