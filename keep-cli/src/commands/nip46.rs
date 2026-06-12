// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! NIP-46 bunker app management CLI: pre-grant, list, and revoke
//! client permissions so headless bunkers don't depend on an interactive
//! approval prompt.

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{KeepError, Result};
use keep_core::hidden::HiddenStorage;
use keep_core::relay::{
    RelayConfig, StoredBunkerPermission, StoredPermissionDuration, GLOBAL_RELAY_KEY,
};
use keep_core::Keep;

use super::{get_password, is_hidden_vault};
use crate::output::Output;

/// Vault dispatch for NIP-46 grant management. Hidden-init vaults route
/// through `HiddenStorage`'s outer volume so the same `keep nip46` CLI
/// surface works regardless of vault layout. Hidden-volume relay-config
/// storage is a deferred follow-up; until then, `keep nip46 grant` on a
/// hidden-init vault always targets the outer volume.
enum NipVault {
    Keep(Box<Keep>),
    HiddenOuter(Box<HiddenStorage>),
}

impl NipVault {
    fn open_unlock(path: &Path, password: &str) -> Result<Self> {
        if is_hidden_vault(path) {
            let mut storage = HiddenStorage::open(path)?;
            storage.unlock_outer(password)?;
            Ok(Self::HiddenOuter(Box::new(storage)))
        } else {
            let mut keep = Keep::open(path)?;
            keep.unlock(password)?;
            Ok(Self::Keep(Box::new(keep)))
        }
    }

    fn get_relay_config_or_default(&self, key: &[u8; 32]) -> Result<RelayConfig> {
        match self {
            Self::Keep(k) => k.get_relay_config_or_default(key),
            Self::HiddenOuter(s) => s.get_relay_config_or_default(key),
        }
    }

    fn store_relay_config(&self, cfg: &RelayConfig) -> Result<()> {
        match self {
            Self::Keep(k) => k.store_relay_config(cfg),
            Self::HiddenOuter(s) => s.store_relay_config(cfg),
        }
    }
}

/// Display all persisted NIP-46 client grants.
pub fn cmd_nip46_apps(out: &Output, path: &Path) -> Result<()> {
    let password = get_password("Enter password")?;
    let vault = NipVault::open_unlock(path, password.expose_secret())?;

    let cfg = vault.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;

    out.newline();
    if !cfg.auto_approve_kinds.is_empty() {
        out.field(
            "Global auto-approve kinds",
            &cfg.auto_approve_kinds
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        out.newline();
    }

    if cfg.bunker_permissions.is_empty() {
        out.info("No NIP-46 client app grants stored.");
        out.info("Pre-grant a client via: keep nip46 grant <pubkey> --name 'X'");
        return Ok(());
    }

    out.header(&format!(
        "NIP-46 client app grants ({})",
        cfg.bunker_permissions.len()
    ));
    for app in &cfg.bunker_permissions {
        out.newline();
        out.field("Pubkey", &app.pubkey_hex);
        out.field("Name", &app.name);
        out.field("Permissions", &format_permissions(app.permissions));
        if !app.auto_approve_kinds.is_empty() {
            out.field(
                "Auto-approve kinds",
                &app.auto_approve_kinds
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        out.field("Duration", &format_duration(&app.duration));
    }
    Ok(())
}

/// Pre-grant a NIP-46 client app a set of permissions.
#[allow(clippy::too_many_arguments)]
pub fn cmd_nip46_grant(
    out: &Output,
    path: &Path,
    pubkey: &str,
    name: &str,
    permissions: &str,
    auto_approve_kinds: &str,
    duration: &str,
) -> Result<()> {
    debug!(pubkey, name, permissions, duration, "nip46 grant");

    let pubkey_hex = parse_pubkey_hex(pubkey)?;
    let permission_bits = parse_permissions(permissions)?;
    let auto_kinds = parse_auto_approve_kinds(auto_approve_kinds)?;
    let parsed_duration = parse_duration(duration)?;

    let password = get_password("Enter password")?;
    let vault = NipVault::open_unlock(path, password.expose_secret())?;

    let mut cfg = vault.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;

    // Upsert: replace existing entry for this pubkey, or append a new one.
    // A 0 fallback would make a `Seconds(n)` grant expire from the epoch (i.e.
    // immediately), so propagate a backwards clock rather than persisting a
    // grant that can never activate.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| KeepError::InvalidInput(format!("system clock before unix epoch: {e}")))?;
    let existing = cfg
        .bunker_permissions
        .iter()
        .position(|p| p.pubkey_hex.eq_ignore_ascii_case(&pubkey_hex));
    let entry = StoredBunkerPermission {
        pubkey_hex: pubkey_hex.clone(),
        name: name.to_string(),
        permissions: permission_bits,
        auto_approve_kinds: auto_kinds,
        duration: parsed_duration,
        connected_at: now,
        timed_kind_grants: Vec::new(),
    };
    let replaced = match existing {
        Some(idx) => {
            cfg.bunker_permissions[idx] = entry;
            true
        }
        None => {
            cfg.bunker_permissions.push(entry);
            false
        }
    };

    vault.store_relay_config(&cfg)?;

    out.newline();
    if replaced {
        out.success(&format!("Updated grant for app {pubkey_hex}"));
    } else {
        out.success(&format!("Granted permissions to app {pubkey_hex}"));
    }
    out.field("Name", name);
    out.field("Permissions", &format_permissions(permission_bits));
    Ok(())
}

/// Revoke a NIP-46 client app's stored permissions.
pub fn cmd_nip46_revoke(out: &Output, path: &Path, pubkey: &str) -> Result<()> {
    let pubkey_hex = parse_pubkey_hex(pubkey)?;

    let password = get_password("Enter password")?;
    let vault = NipVault::open_unlock(path, password.expose_secret())?;

    let mut cfg = vault.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;
    let before = cfg.bunker_permissions.len();
    cfg.bunker_permissions
        .retain(|p| !p.pubkey_hex.eq_ignore_ascii_case(&pubkey_hex));
    let after = cfg.bunker_permissions.len();

    if before == after {
        return Err(KeepError::KeyNotFound(format!(
            "no NIP-46 grant found for pubkey {pubkey_hex}"
        )));
    }

    vault.store_relay_config(&cfg)?;
    out.newline();
    out.success(&format!("Revoked NIP-46 grant for app {pubkey_hex}"));
    Ok(())
}

/// Set the global list of event kinds auto-approved for every NIP-46 client.
pub fn cmd_nip46_auto_approve(out: &Output, path: &Path, kinds: &str) -> Result<()> {
    let parsed = parse_auto_approve_kinds(kinds)?;

    let password = get_password("Enter password")?;
    let vault = NipVault::open_unlock(path, password.expose_secret())?;

    let mut cfg = vault.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;
    cfg.auto_approve_kinds = parsed.clone();
    vault.store_relay_config(&cfg)?;

    out.newline();
    if parsed.is_empty() {
        out.success("Cleared the global auto-approve kinds list.");
    } else {
        out.success("Updated global auto-approve kinds.");
        out.field(
            "Kinds",
            &parsed
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    Ok(())
}

fn parse_pubkey_hex(input: &str) -> Result<String> {
    if input.starts_with("npub1") {
        let bytes = keep_core::keys::npub_to_bytes(input)?;
        Ok(hex::encode(bytes))
    } else {
        let bytes = hex::decode(input).map_err(|e| {
            KeepError::InvalidInput(format!("expected npub or 32-byte hex pubkey: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(KeepError::InvalidInput(format!(
                "pubkey must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(hex::encode(bytes))
    }
}

fn parse_permissions(s: &str) -> Result<u32> {
    let mut perms = keep_nip46::Permission::empty();
    for token in s.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let flag = keep_nip46::Permission::from_canonical_name(token).ok_or_else(|| {
            let known = keep_nip46::Permission::NAMES
                .iter()
                .map(|(_, n)| *n)
                .collect::<Vec<_>>()
                .join(", ");
            KeepError::InvalidInput(format!("unknown permission '{token}'; valid: {known}, all"))
        })?;
        perms |= flag;
    }
    if perms.is_empty() {
        return Err(KeepError::InvalidInput(
            "at least one permission must be granted".into(),
        ));
    }
    Ok(perms.bits())
}

fn parse_auto_approve_kinds(s: &str) -> Result<Vec<u16>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| {
            t.parse::<u16>().map_err(|_| {
                KeepError::InvalidInput(format!("invalid event kind '{t}'; expected u16"))
            })
        })
        .collect()
}

fn parse_duration(s: &str) -> Result<StoredPermissionDuration> {
    match s.to_ascii_lowercase().as_str() {
        "session" => Ok(StoredPermissionDuration::Session),
        "forever" | "permanent" => Ok(StoredPermissionDuration::Forever),
        n => {
            let secs = n.parse::<u64>().map_err(|_| {
                KeepError::InvalidInput(format!(
                    "duration must be 'session', 'forever', or a u64 of seconds; got '{n}'"
                ))
            })?;
            Ok(StoredPermissionDuration::Seconds(secs))
        }
    }
}

fn format_permissions(bits: u32) -> String {
    keep_nip46::Permission::from_bits_truncate(bits).to_names()
}

fn format_duration(d: &StoredPermissionDuration) -> String {
    match d {
        StoredPermissionDuration::Session => "session".to_string(),
        StoredPermissionDuration::Forever => "forever".to_string(),
        StoredPermissionDuration::Seconds(s) => format!("{s}s"),
    }
}
