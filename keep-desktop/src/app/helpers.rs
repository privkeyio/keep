// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use iced::Task;
use tracing::error;

use crate::message::Message;
use crate::screen::nsec_keys::NsecKeyEntry;
use crate::screen::shares::ShareEntry;
use crate::screen::{import, nsec_keys, Screen};

use std::sync::atomic::Ordering;

use super::config::{migrate_json_config_to_vault, save_settings};
use super::util::{collect_shares, default_bunker_relays, lock_keep, parse_hex_key};
use super::{App, Toast, ToastKind, PROXY_SESSION_TIMEOUT, TOAST_DURATION_SECS};

impl App {
    pub(super) fn do_lock(&mut self) -> Task<Message> {
        self.stop_scanner();
        self.handle_disconnect_relay();
        self.stop_bunker();
        #[cfg(unix)]
        self.stop_local_signer();

        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            keep.lock();
        }
        *guard = None;
        drop(guard);
        let clear_clipboard = self.clipboard_clear_at.take().is_some();
        self.active_share_hex = None;
        self.active_coordinations.clear();
        self.peer_xpubs.clear();
        self.identities.clear();
        self.cached_share_count = 0;
        self.cached_nsec_count = 0;
        self.identity_switcher_open = false;
        self.delete_identity_confirm = None;
        self.toast = None;
        self.toast_dismiss_at = None;
        self.scanner_recovery = None;
        self.distribute_state = None;
        self.distribute_export_id = None;
        self.pending_vault_share = None;
        self.frost_last_share = None;
        self.frost_last_relay_urls = None;
        self.nostrconnect_pending = None;
        self.bunker_pending_setup = None;
        self.pin_mismatch = None;
        self.pin_mismatch_confirm = false;
        self.bunker_cert_pin_failed = false;
        self.screen = Screen::Unlock(crate::screen::unlock::State::new(true));
        if clear_clipboard {
            iced::clipboard::write(String::new())
        } else {
            Task::none()
        }
    }

    pub(super) fn current_shares(&self) -> Vec<ShareEntry> {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return Vec::new();
        };
        collect_shares(keep).unwrap_or_else(|e| {
            error!("Failed to list shares: {e}");
            Vec::new()
        })
    }

    pub(super) fn build_import_summaries(&self) -> Vec<import::ExistingShareSummary> {
        self.current_shares()
            .iter()
            .map(|s| import::ExistingShareSummary {
                group_pubkey_hex: s.group_pubkey_hex.clone(),
                name: s.name.clone(),
                identifier: s.identifier,
            })
            .collect()
    }

    pub(super) fn refresh_shares(&mut self) {
        let shares = self.current_shares();
        self.cached_share_count = shares.len();
        self.cached_nsec_count = self.current_nsec_keys().len();
        self.resolve_active_share(&shares);
        self.refresh_identities(&shares);
        if matches!(self.screen, Screen::NsecKeys(_)) {
            self.set_nsec_keys_screen();
        } else if let Screen::ShareList(s) = &mut self.screen {
            s.refresh(shares, self.active_share_hex.clone());
        }
    }

    pub(super) fn set_share_screen(&mut self, shares: Vec<ShareEntry>) {
        self.cached_share_count = shares.len();
        self.cached_nsec_count = self.current_nsec_keys().len();
        self.resolve_active_share(&shares);
        self.refresh_identities(&shares);
        self.screen = Screen::ShareList(crate::screen::shares::State::new(
            shares,
            self.active_share_hex.clone(),
        ));
    }

    pub(super) fn current_nsec_keys(&self) -> Vec<NsecKeyEntry> {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return Vec::new();
        };
        keep.list_keys()
            .unwrap_or_default()
            .iter()
            .filter_map(NsecKeyEntry::from_record)
            .collect()
    }

    pub(super) fn set_nsec_keys_screen(&mut self) {
        let keys = self.current_nsec_keys();
        self.cached_nsec_count = keys.len();
        self.screen =
            Screen::NsecKeys(nsec_keys::State::new(keys, self.active_share_hex.clone()));
    }

    pub(super) fn resolve_active_share(&mut self, shares: &[ShareEntry]) {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else {
            return;
        };

        let current = keep.get_active_share_key();
        let still_valid = current
            .as_ref()
            .is_some_and(|key| shares.iter().any(|s| s.group_pubkey_hex == *key));

        if still_valid {
            self.active_share_hex = current;
            return;
        }

        let first = shares.first().map(|s| s.group_pubkey_hex.as_str());
        let all_same_group =
            first.is_some_and(|f| shares.iter().all(|s| s.group_pubkey_hex == f));
        let new_key = if all_same_group { first } else { None };

        match keep.set_active_share_key(new_key) {
            Ok(()) => self.active_share_hex = new_key.map(String::from),
            Err(e) => {
                tracing::warn!("Failed to persist active share: {e}");
                self.active_share_hex = None;
            }
        }
    }

    pub(crate) fn set_toast(&mut self, message: String, kind: ToastKind) {
        self.toast = Some(Toast { message, kind });
        self.toast_dismiss_at = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
    }

    pub(crate) fn proxy_addr(&self) -> Option<SocketAddr> {
        if self.proxy_enabled && self.proxy_port > 0 {
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, self.proxy_port)))
        } else {
            None
        }
    }

    pub(crate) fn frost_channels(&self) -> crate::frost::FrostChannels {
        crate::frost::FrostChannels {
            events: self.frost_events.clone(),
            pending_requests: self.pending_sign_requests.clone(),
            shutdown: self.frost_shutdown.clone(),
        }
    }

    pub(crate) fn network_config(&self) -> crate::frost::NetworkConfig {
        crate::frost::NetworkConfig {
            proxy: self.proxy_addr(),
            session_timeout: if self.proxy_enabled {
                Some(PROXY_SESSION_TIMEOUT)
            } else {
                None
            },
            certificate_pins: self.certificate_pins.clone(),
            keep_path: self.keep_path.clone(),
        }
    }

    pub(crate) fn active_group_pubkey_bytes(&self) -> Option<[u8; 32]> {
        self.active_share_hex.as_deref().and_then(parse_hex_key)
    }

    pub(crate) fn update_relay_config(&self, f: impl FnOnce(&mut keep_core::RelayConfig)) {
        let guard = lock_keep(&self.keep);
        let Some(keep) = guard.as_ref() else { return };
        let key = self
            .active_group_pubkey_bytes()
            .unwrap_or(keep_core::GLOBAL_RELAY_KEY);
        let mut config = match keep.get_relay_config(&key) {
            Ok(Some(c)) => c,
            Ok(None) => keep_core::RelayConfig::new(key),
            Err(e) => {
                tracing::error!("Failed to read relay config: {e}");
                return;
            }
        };
        f(&mut config);
        if let Err(e) = keep.store_relay_config(&config) {
            tracing::error!("Failed to save relay config: {e}");
        }
    }

    pub(crate) fn save_relay_urls(&self) {
        let urls = self.relay_urls.clone();
        self.update_relay_config(|config| config.frost_relays = urls);
    }

    pub(super) fn save_peer_policy(
        &self,
        pubkey_hex: &str,
        allow_send: bool,
        allow_receive: bool,
    ) {
        let hex = pubkey_hex.to_string();
        self.update_relay_config(|config| {
            if let Some(existing) = config
                .peer_policies
                .iter_mut()
                .find(|p| p.pubkey_hex == hex)
            {
                existing.allow_send = allow_send;
                existing.allow_receive = allow_receive;
            } else {
                config.peer_policies.push(keep_core::PeerPolicyEntry {
                    pubkey_hex: hex,
                    allow_send,
                    allow_receive,
                });
            }
        });
    }

    pub(crate) fn save_bunker_relays(&self) {
        let relays = self.bunker_relays.clone();
        self.update_relay_config(|config| config.bunker_relays = relays);
    }

    pub(super) fn save_proxy_config(&self) {
        let guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_ref() {
            let proxy = keep_core::ProxyConfig {
                enabled: self.proxy_enabled,
                port: self.proxy_port,
            };
            if let Err(e) = keep.set_proxy_config(&proxy) {
                tracing::error!("Failed to save proxy config: {e}");
            }
        }
    }

    pub(crate) fn start_clipboard_timer(&mut self) {
        self.clipboard_clear_at = if self.settings.clipboard_clear_secs > 0 {
            Some(Instant::now() + Duration::from_secs(self.settings.clipboard_clear_secs))
        } else {
            None
        };
    }

    pub(super) fn apply_relay_config(&mut self, config: keep_core::RelayConfig) {
        self.relay_urls = config.frost_relays;
        self.bunker_relays = if config.bunker_relays.is_empty() {
            default_bunker_relays()
        } else {
            config.bunker_relays
        };
        self.saved_peer_policies = config.peer_policies;
    }

    pub(super) fn load_config_from_vault(&mut self) {
        let (relay_config, proxy) = {
            let guard = lock_keep(&self.keep);
            let Some(keep) = guard.as_ref() else {
                return;
            };

            migrate_json_config_to_vault(keep, &self.keep_path);

            let key = self
                .active_group_pubkey_bytes()
                .unwrap_or(keep_core::GLOBAL_RELAY_KEY);
            let relay_config = keep
                .get_relay_config_or_default(&key)
                .unwrap_or_else(|_| keep_core::RelayConfig::with_defaults(key));
            let proxy = keep.get_proxy_config().unwrap_or_default();
            (relay_config, proxy)
        };
        self.apply_relay_config(relay_config);
        self.proxy_enabled = proxy.enabled;
        self.proxy_port = proxy.port;
    }

    pub(super) fn reconcile_kill_switch(&mut self) {
        let vault_state = {
            let guard = lock_keep(&self.keep);
            match guard.as_ref().and_then(|k| k.get_kill_switch().ok()) {
                Some(state) => state,
                None => return,
            }
        };
        self.kill_switch.store(vault_state, Ordering::Release);
        if self.settings.kill_switch_active != vault_state {
            self.settings.kill_switch_active = vault_state;
            save_settings(&self.keep_path, &self.settings);
        }
    }

    pub(crate) fn is_kill_switch_active(&self) -> bool {
        self.kill_switch.load(Ordering::Acquire)
    }
}
