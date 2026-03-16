// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use super::util::{parse_hex_key, write_private};
use super::{AUTO_LOCK_SECS, CLIPBOARD_CLEAR_SECS, DEFAULT_PROXY_PORT};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Settings {
    #[serde(default = "default_auto_lock_secs")]
    pub auto_lock_secs: u64,
    #[serde(default = "default_clipboard_clear_secs")]
    pub clipboard_clear_secs: u64,
    #[serde(default)]
    pub kill_switch_active: bool,
    #[serde(default)]
    pub minimize_to_tray: bool,
    #[serde(default)]
    pub start_minimized: bool,
    #[serde(default)]
    pub bunker_auto_start: bool,
    #[serde(default)]
    pub local_signer_auto_start: bool,
}

fn default_auto_lock_secs() -> u64 {
    AUTO_LOCK_SECS
}

fn default_clipboard_clear_secs() -> u64 {
    CLIPBOARD_CLEAR_SECS
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: AUTO_LOCK_SECS,
            clipboard_clear_secs: CLIPBOARD_CLEAR_SECS,
            kill_switch_active: false,
            minimize_to_tray: false,
            start_minimized: false,
            bunker_auto_start: false,
            local_signer_auto_start: false,
        }
    }
}

pub(crate) fn settings_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("settings.json")
}

pub(crate) fn load_settings(keep_path: &std::path::Path) -> (Settings, bool) {
    let path = settings_path(keep_path);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return (Settings::default(), false);
    };
    let settings: Settings = serde_json::from_str(&contents).unwrap_or_default();
    let migrated = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .map(|v| v.get("minimize_to_tray").is_none())
        .unwrap_or(false);
    if migrated {
        save_settings(keep_path, &settings);
        tracing::info!("Settings migrated: minimize_to_tray now defaults to off");
    }
    (settings, migrated)
}

pub(crate) fn save_settings(keep_path: &std::path::Path, settings: &Settings) {
    let path = settings_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save settings to {}: {e}", path.display());
        }
    }
}

pub(crate) fn migrate_json_config_to_vault(
    keep: &keep_core::Keep,
    keep_path: &std::path::Path,
) {
    let global_exists = match keep.get_relay_config(&keep_core::GLOBAL_RELAY_KEY) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("Failed to check existing relay config, skipping migration: {e}");
            return;
        }
    };

    if !global_exists {
        let mut config = keep_core::RelayConfig::new_global();

        let relay_path = keep_path.join("relays.json");
        if let Ok(contents) = std::fs::read_to_string(&relay_path) {
            if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                if !urls.is_empty() {
                    config.frost_relays = urls;
                }
            }
        }

        let bunker_path = keep_path.join("bunker-relays.json");
        if let Ok(contents) = std::fs::read_to_string(&bunker_path) {
            if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                if !urls.is_empty() {
                    config.bunker_relays = urls;
                }
            }
        }

        match keep.store_relay_config(&config) {
            Ok(()) => {
                let _ = std::fs::remove_file(&relay_path);
                let _ = std::fs::remove_file(&bunker_path);
            }
            Err(e) => {
                tracing::warn!("Failed to migrate global relay config to vault: {e}");
            }
        }
    }

    let settings_path = keep_path.join("settings.json");
    if let Ok(contents) = std::fs::read_to_string(&settings_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            let enabled = json
                .get("proxy_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let port = json
                .get("proxy_port")
                .and_then(|v| v.as_u64())
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(DEFAULT_PROXY_PORT);
            if enabled || port != DEFAULT_PROXY_PORT {
                let proxy = keep_core::ProxyConfig { enabled, port };
                if let Err(e) = keep.set_proxy_config(&proxy) {
                    tracing::warn!(
                        enabled,
                        port,
                        "Failed to migrate proxy config to vault: {e}"
                    );
                }
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir(keep_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Some(hex) = name_str
                .strip_prefix("relays-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Some(key) = parse_hex_key(hex) else {
                continue;
            };
            let mut per_key_config = keep_core::RelayConfig::new(key);
            if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                    per_key_config.frost_relays = urls;
                }
            }
            let bunker_file = keep_path.join(format!("bunker-relays-{hex}.json"));
            if let Ok(contents) = std::fs::read_to_string(&bunker_file) {
                if let Ok(urls) = serde_json::from_str::<Vec<String>>(&contents) {
                    per_key_config.bunker_relays = urls;
                }
            }
            match keep.store_relay_config(&per_key_config) {
                Ok(()) => {
                    let _ = std::fs::remove_file(entry.path());
                    let _ = std::fs::remove_file(&bunker_file);
                }
                Err(e) => {
                    tracing::warn!("Failed to migrate relay config for {hex}: {e}");
                }
            }
        }
    }

    tracing::info!("Migrated relay/proxy config from JSON files to vault");
}
