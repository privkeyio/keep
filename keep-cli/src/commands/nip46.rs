// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! NIP-46 bunker app management CLI: pre-grant, list, and revoke
//! client permissions so headless bunkers don't depend on an interactive
//! approval prompt.

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{KeepError, Result};
use keep_core::relay::{StoredBunkerPermission, StoredPermissionDuration, GLOBAL_RELAY_KEY};
use keep_core::Keep;

use super::get_password;
use crate::output::Output;

/// Display all persisted NIP-46 client grants.
pub fn cmd_nip46_apps(out: &Output, path: &Path) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;

    let cfg = keep.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;
    if cfg.bunker_permissions.is_empty() {
        out.newline();
        out.info("No NIP-46 client app grants stored.");
        out.info("Pre-grant a client via: keep nip46 grant <pubkey> --name 'X'");
        return Ok(());
    }

    out.newline();
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

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;

    let mut cfg = keep.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;

    // Upsert: replace existing entry for this pubkey, or append a new one.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

    keep.store_relay_config(&cfg)?;

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

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;

    let mut cfg = keep.get_relay_config_or_default(&GLOBAL_RELAY_KEY)?;
    let before = cfg.bunker_permissions.len();
    cfg.bunker_permissions
        .retain(|p| !p.pubkey_hex.eq_ignore_ascii_case(&pubkey_hex));
    let after = cfg.bunker_permissions.len();

    if before == after {
        return Err(KeepError::KeyNotFound(format!(
            "no NIP-46 grant found for pubkey {pubkey_hex}"
        )));
    }

    keep.store_relay_config(&cfg)?;
    out.newline();
    out.success(&format!("Revoked NIP-46 grant for app {pubkey_hex}"));
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
    let mut bits: u32 = 0;
    for token in s.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let lower = token.to_ascii_lowercase();
        let bit = match lower.as_str() {
            "all" => return Ok(0b00111111),
            "get_public_key" | "getpublickey" => 0b00000001,
            "sign_event" | "signevent" => 0b00000010,
            "nip04_encrypt" | "nip04encrypt" => 0b00000100,
            "nip04_decrypt" | "nip04decrypt" => 0b00001000,
            "nip44_encrypt" | "nip44encrypt" => 0b00010000,
            "nip44_decrypt" | "nip44decrypt" => 0b00100000,
            other => {
                return Err(KeepError::InvalidInput(format!(
                    "unknown permission '{other}'; valid: get_public_key, sign_event, nip04_encrypt, nip04_decrypt, nip44_encrypt, nip44_decrypt, all"
                )));
            }
        };
        bits |= bit;
    }
    if bits == 0 {
        return Err(KeepError::InvalidInput(
            "at least one permission must be granted".into(),
        ));
    }
    Ok(bits)
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
    const NAMES: &[(u32, &str)] = &[
        (0b00000001, "get_public_key"),
        (0b00000010, "sign_event"),
        (0b00000100, "nip04_encrypt"),
        (0b00001000, "nip04_decrypt"),
        (0b00010000, "nip44_encrypt"),
        (0b00100000, "nip44_decrypt"),
    ];
    let set: Vec<&str> = NAMES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() {
        "(none)".to_string()
    } else {
        set.join(",")
    }
}

fn format_duration(d: &StoredPermissionDuration) -> String {
    match d {
        StoredPermissionDuration::Session => "session".to_string(),
        StoredPermissionDuration::Forever => "forever".to_string(),
        StoredPermissionDuration::Seconds(s) => format!("{s}s"),
    }
}
