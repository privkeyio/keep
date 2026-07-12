// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use keep_core::Keep;
use keep_nip46::NostrConnectRequest;
use tracing::error;

use crate::screen::shares::ShareEntry;
use crate::screen::signing_audit::AuditDisplayEntry;

static PENDING_NOSTRCONNECT: OnceLock<Mutex<Option<NostrConnectRequest>>> = OnceLock::new();

pub fn set_pending_nostrconnect(request: Option<NostrConnectRequest>) {
    let cell = PENDING_NOSTRCONNECT.get_or_init(|| Mutex::new(None));
    match cell.lock() {
        Ok(mut guard) => *guard = request,
        Err(e) => {
            tracing::warn!("nostrconnect mutex poisoned, recovering");
            *e.into_inner() = request;
        }
    }
}

pub(crate) fn take_pending_nostrconnect() -> Option<NostrConnectRequest> {
    let cell = PENDING_NOSTRCONNECT.get()?;
    match cell.lock() {
        Ok(mut guard) => guard.take(),
        Err(e) => e.into_inner().take(),
    }
}

pub(crate) fn lock_keep(
    keep: &Arc<Mutex<Option<Keep>>>,
) -> std::sync::MutexGuard<'_, Option<Keep>> {
    match keep.lock() {
        Ok(guard) => guard,
        Err(e) => {
            let mut guard = e.into_inner();
            if let Some(ref mut k) = *guard {
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| k.lock()));
            }
            *guard = None;
            guard
        }
    }
}

pub(crate) fn friendly_err(e: keep_core::error::KeepError) -> String {
    use keep_core::error::KeepError;
    match &e {
        KeepError::InvalidPassword => "Invalid password".into(),
        KeepError::RateLimited(secs) => format!("Too many attempts. Try again in {secs} seconds"),
        KeepError::DecryptionFailed => {
            "Decryption failed - wrong password or corrupted data".into()
        }
        KeepError::Locked => "Vault is locked".into(),
        KeepError::Database(msg) => {
            tracing::warn!("Database error: {msg}");
            "Database error".into()
        }
        KeepError::AlreadyExists(_) => "Vault already exists".into(),
        KeepError::NotFound(_) => "Vault not found".into(),
        KeepError::InvalidInput(msg) => format!("Invalid input: {msg}"),
        KeepError::InvalidNsec => "Invalid secret key format".into(),
        KeepError::InvalidNpub(detail) => format!("Invalid public key: {detail}"),
        KeepError::KeyAlreadyExists(_) => "A key with this name already exists".into(),
        KeepError::KeyNotFound(_) => "Key not found".into(),
        KeepError::KeyringFull(_) => "Keyring is full".into(),
        KeepError::Frost(_) | KeepError::FrostErr(_) => "FROST operation failed".into(),
        KeepError::PermissionDenied(_) => "Permission denied".into(),
        KeepError::HomeNotFound => "Home directory not found".into(),
        KeepError::UserRejected => "Operation cancelled".into(),
        KeepError::Io(_) => "File system error".into(),
        _ => {
            tracing::warn!("Unmapped keep error: {e}");
            "Operation failed".into()
        }
    }
}

pub(crate) fn write_private_bytes(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(path);
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    (&tmp).write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub(crate) fn to_display_entry(e: keep_core::audit::SigningAuditEntry) -> AuditDisplayEntry {
    AuditDisplayEntry {
        timestamp: e.timestamp,
        request_type: e.request_type.to_string(),
        decision: e.decision.to_string(),
        was_automatic: e.was_automatic,
        caller: e.caller,
        caller_name: e.caller_name,
        event_kind: e.event_kind,
    }
}

pub(crate) fn collect_shares(keep: &Keep) -> Result<Vec<ShareEntry>, String> {
    keep.frost_list_shares()
        .map(|stored| stored.iter().map(ShareEntry::from_stored).collect())
        .map_err(friendly_err)
}

pub(crate) fn with_keep_blocking<T: Send + 'static>(
    keep_arc: &Arc<Mutex<Option<Keep>>>,
    panic_msg: &'static str,
    f: impl FnOnce(&mut Keep) -> Result<T, String> + Send + std::panic::UnwindSafe + 'static,
) -> Result<T, String> {
    let mut keep = lock_keep(keep_arc)
        .take()
        .ok_or_else(|| "Keep not available".to_string())?;

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| f(&mut keep)));

    match result {
        Ok(r) => {
            *lock_keep(keep_arc) = Some(keep);
            r
        }
        Err(payload) => {
            let detail = payload
                .downcast::<String>()
                .map(|s| *s)
                .or_else(|p| p.downcast::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|_| "unknown".to_string());
            error!("{panic_msg}: {detail}");
            Err(format!("{panic_msg}; please re-unlock your vault"))
        }
    }
}

pub(crate) fn cert_pins_path(keep_path: &std::path::Path) -> PathBuf {
    keep_path.join("cert-pins.json")
}

pub(crate) fn load_cert_pins(keep_path: &std::path::Path) -> keep_frost_net::CertificatePinSet {
    let path = cert_pins_path(keep_path);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return keep_frost_net::CertificatePinSet::new();
    };
    match keep_frost_net::CertificatePinSet::from_json_bytes(contents.as_bytes()) {
        Ok((pins, malformed)) => {
            if !malformed.is_empty() {
                tracing::warn!(
                    "Dropping malformed certificate pins: {}",
                    malformed.join(", ")
                );
            }
            pins
        }
        Err(e) => {
            tracing::warn!("Failed to parse certificate pins: {e}");
            keep_frost_net::CertificatePinSet::new()
        }
    }
}

/// Corruption status of the on-disk certificate-pin store.
///
/// Returns `None` when the file is absent (first run: no pins yet) or parses
/// cleanly with no malformed entries. Returns `Some(reasons)` when the file
/// exists but fails to parse, or parses with one or more malformed entries.
///
/// This is the fail-closed counterpart to [`load_cert_pins`], which drops
/// malformed entries so valid pins still load. A corrupt store must not
/// silently downgrade a previously-pinned host to trust-on-first-use: dropping
/// a host's only (corrupted) entry would let `verify_relay_certificate` re-pin
/// whatever certificate an on-path attacker presents. The connect path checks
/// this and refuses, mirroring keep-mobile, whose `load_cert_pins` returns
/// `Err` on any malformed entry.
pub(crate) fn cert_pin_store_corruption(keep_path: &std::path::Path) -> Option<Vec<String>> {
    let path = cert_pins_path(keep_path);
    // Absent file is a legitimate first-run state, not corruption.
    let contents = std::fs::read_to_string(&path).ok()?;
    match keep_frost_net::CertificatePinSet::from_json_bytes(contents.as_bytes()) {
        Ok((_, malformed)) if malformed.is_empty() => None,
        Ok((_, malformed)) => Some(malformed),
        Err(e) => Some(vec![format!("parse error: {e}")]),
    }
}

pub(crate) fn save_cert_pins(
    keep_path: &std::path::Path,
    pins: &keep_frost_net::CertificatePinSet,
) {
    let path = cert_pins_path(keep_path);
    if let Ok(json) = serde_json::to_string_pretty(&pins.to_hex_map()) {
        if let Err(e) = write_private(&path, &json) {
            tracing::error!("Failed to save certificate pins: {e}");
        }
    }
}

pub(crate) fn parse_hex_key(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

pub(crate) fn write_private(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or(path);
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        use std::io::Write;
        tmp.write_all(data.as_bytes())?;
        tmp.as_file().sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.persist(path).map_err(std::io::Error::other)?;
    Ok(())
}

pub(crate) fn default_bunker_relays() -> Vec<String> {
    super::DEFAULT_BUNKER_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_store(dir: &std::path::Path, json: &str) {
        std::fs::write(cert_pins_path(dir), json).unwrap();
    }

    #[test]
    fn corruption_none_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        // First run: no cert-pins.json yet is not corruption.
        assert!(cert_pin_store_corruption(dir.path()).is_none());
    }

    #[test]
    fn corruption_none_for_valid_store() {
        let dir = tempfile::tempdir().unwrap();
        let hash = "aa".repeat(32);
        write_store(dir.path(), &format!(r#"{{"relay.example.com":["{hash}"]}}"#));
        assert!(cert_pin_store_corruption(dir.path()).is_none());
        // And the valid pin still loads (parity: healthy files unaffected).
        assert!(load_cert_pins(dir.path()).is_pinned("relay.example.com"));
    }

    #[test]
    fn corruption_some_for_malformed_entry() {
        let dir = tempfile::tempdir().unwrap();
        // A previously-pinned host whose only entry no longer decodes to a hash.
        write_store(dir.path(), r#"{"relay.example.com":"nothex"}"#);
        let reasons = cert_pin_store_corruption(dir.path()).expect("malformed => corrupt");
        assert!(reasons.iter().any(|r| r.contains("relay.example.com")));
        // The host must not silently survive as an unpinned (TOFU) host.
        assert!(!load_cert_pins(dir.path()).is_pinned("relay.example.com"));
    }

    #[test]
    fn corruption_some_for_unparseable_json() {
        let dir = tempfile::tempdir().unwrap();
        write_store(dir.path(), "{ this is not json");
        let reasons = cert_pin_store_corruption(dir.path()).expect("bad json => corrupt");
        assert!(reasons.iter().any(|r| r.contains("parse error")));
    }
}
