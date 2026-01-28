// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Permission: u32 {
        const GET_PUBLIC_KEY = 0b00000001;
        const SIGN_EVENT     = 0b00000010;
        const NIP04_ENCRYPT  = 0b00000100;
        const NIP04_DECRYPT  = 0b00001000;
        const NIP44_ENCRYPT  = 0b00010000;
        const NIP44_DECRYPT  = 0b00100000;

        const DEFAULT = Self::GET_PUBLIC_KEY.bits()
                      | Self::SIGN_EVENT.bits()
                      | Self::NIP44_ENCRYPT.bits()
                      | Self::NIP44_DECRYPT.bits();

        const ALL = Self::GET_PUBLIC_KEY.bits()
                  | Self::SIGN_EVENT.bits()
                  | Self::NIP04_ENCRYPT.bits()
                  | Self::NIP04_DECRYPT.bits()
                  | Self::NIP44_ENCRYPT.bits()
                  | Self::NIP44_DECRYPT.bits();
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
}

impl AppPermission {
    pub fn new(pubkey: PublicKey, name: String) -> Self {
        Self {
            pubkey,
            name,
            permissions: Permission::DEFAULT,
            auto_approve_kinds: HashSet::from([Kind::Reaction, Kind::RelayList]),
            connected_at: Timestamp::now(),
            last_used: Timestamp::now(),
            request_count: 0,
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
            global_auto_approve: HashSet::from([Kind::Reaction, Kind::RelayList]),
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

    pub fn connect(&mut self, pubkey: PublicKey, name: String) {
        self.apps
            .entry(pubkey)
            .or_insert_with(|| AppPermission::new(pubkey, name));
    }

    #[allow(dead_code)]
    pub fn revoke(&mut self, pubkey: &PublicKey) {
        self.apps.remove(pubkey);
    }

    pub fn has_permission(&self, pubkey: &PublicKey, perm: Permission) -> bool {
        self.apps
            .get(pubkey)
            .map(|app| app.permissions.contains(perm))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_connected(&self, pubkey: &PublicKey) -> bool {
        self.apps.contains_key(pubkey)
    }

    pub fn needs_approval(&self, pubkey: &PublicKey, kind: Kind) -> bool {
        if self.global_auto_approve.contains(&kind) {
            return false;
        }

        if let Some(app) = self.apps.get(pubkey) {
            if app.auto_approve_kinds.contains(&kind) {
                return false;
            }
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

    #[allow(dead_code)]
    pub fn list_apps(&self) -> impl Iterator<Item = &AppPermission> {
        self.apps.values()
    }

    #[allow(dead_code)]
    pub fn set_auto_approve_kinds(&mut self, kinds: HashSet<Kind>) {
        self.global_auto_approve = kinds;
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
        assert!(pm.has_permission(&pubkey, Permission::SIGN_EVENT));

        assert!(!pm.needs_approval(&pubkey, Kind::Reaction));
        assert!(pm.needs_approval(&pubkey, Kind::TextNote));

        pm.revoke(&pubkey);
        assert!(!pm.is_connected(&pubkey));
    }
}
