// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
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
    pub auto_approve_kinds: HashSet<Kind>,
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
            connected_at: Timestamp::now(),
            last_used: Timestamp::now(),
            request_count: 0,
            duration: PermissionDuration::Forever,
        }
    }
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
        if let Some(app) = self.apps.get_mut(&pubkey) {
            app.permissions |= permissions;
            app.last_used = Timestamp::now();
        } else {
            let mut app = AppPermission::new(pubkey, name);
            app.permissions = permissions;
            self.apps.insert(pubkey, app);
        }
    }

    pub const MAX_CONNECTED_APPS: usize = 100;

    fn evict_expired(&mut self) {
        self.apps
            .retain(|_, app| !app.duration.is_expired(app.connected_at));
    }

    fn ensure_capacity(&mut self, pubkey: &PublicKey) -> bool {
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
            if !app.duration.is_expired(app.connected_at)
                && app.auto_approve_kinds.contains(&kind)
            {
                return false;
            }
        }
        if self.global_auto_approve.contains(&kind) {
            return false;
        }
        true
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

    #[allow(dead_code)]
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

        pm.set_auto_approve_kinds_for_app(
            &pubkey,
            HashSet::from([Kind::TextNote, Kind::Reaction]),
        );
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
}
