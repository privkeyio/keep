use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use secrecy::ExposeSecret;

use keep_core::audit::{AuditEventType, RetentionPolicy};
use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::commands::get_password;
use crate::output::Output;

fn resolve_path(path: &Path, hidden: bool) -> PathBuf {
    if hidden {
        path.join("inner")
    } else {
        path.to_path_buf()
    }
}

fn format_timestamp(timestamp: i64) -> String {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn cmd_audit_list(out: &Output, path: &Path, limit: Option<usize>, hidden: bool) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let entries = keep.audit_read_all()?;
    let display_entries: Vec<_> = if let Some(n) = limit {
        entries.iter().rev().take(n).collect()
    } else {
        entries.iter().rev().collect()
    };

    if display_entries.is_empty() {
        out.info("No audit entries found");
        return Ok(());
    }

    out.info(&format!("Audit log ({} entries):", entries.len()));
    out.newline();

    for entry in display_entries.iter().rev() {
        let time = format_timestamp(entry.timestamp);
        let status = if entry.success { "OK" } else { "FAIL" };

        let mut details = Vec::new();
        if let Some(ref pk) = entry.pubkey {
            details.push(format!("key:{}", &pk[..pk.len().min(8)]));
        }
        if let Some(ref gp) = entry.group_pubkey {
            details.push(format!("group:{}", &gp[..gp.len().min(8)]));
        }
        if let Some(ref mh) = entry.message_hash {
            details.push(format!("msg:{}", &mh[..mh.len().min(8)]));
        }
        if let Some(t) = entry.threshold {
            details.push(format!("t:{t}"));
        }
        if let Some(ref reason) = entry.reason {
            details.push(format!("reason:{reason}"));
        }

        let detail_str = if details.is_empty() {
            String::new()
        } else {
            format!(" [{}]", details.join(", "))
        };

        out.info(&format!(
            "{} {} {}{}",
            time, status, entry.event_type, detail_str
        ));
    }

    Ok(())
}

fn resolve_output_path(out_path: &str) -> Result<PathBuf> {
    use keep_core::error::KeepError;

    let out_path = PathBuf::from(out_path);
    let canonical = if out_path.exists() {
        out_path.canonicalize()?
    } else {
        let parent = out_path
            .parent()
            .unwrap_or(Path::new("."))
            .canonicalize()
            .map_err(|_| KeepError::InvalidInput("output directory does not exist".to_string()))?;
        let file_name = out_path
            .file_name()
            .ok_or_else(|| KeepError::InvalidInput("invalid output path".to_string()))?;
        parent.join(file_name)
    };

    if canonical.to_string_lossy().contains("..") {
        return Err(KeepError::InvalidInput(
            "path traversal detected in output path".to_string(),
        ));
    }

    Ok(canonical)
}

pub fn cmd_audit_export(
    out: &Output,
    path: &Path,
    output_path: Option<&str>,
    hidden: bool,
) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let json = keep.audit_export()?;

    match output_path {
        Some(out_path) => {
            let canonical = resolve_output_path(out_path)?;
            std::fs::write(&canonical, &json)?;
            out.success(&format!("Audit log exported to {}", canonical.display()));
        }
        None => println!("{json}"),
    }

    Ok(())
}

pub fn cmd_audit_verify(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let valid = keep.audit_verify_chain().map_err(map_verify_error)?;

    if valid {
        out.success("Audit log integrity verified - hash chain is valid");
    } else {
        out.error(
            "Audit log integrity check FAILED: hash chain is broken. The audit log was modified after writing. Do NOT trust this vault for anything authoritative until you investigate.",
        );
        std::process::exit(1);
    }

    Ok(())
}

/// Rewrap low-level audit-decode errors with a clear tamper-vs-corruption
/// category instead of leaking parser details that mislead operators.
fn map_verify_error(e: KeepError) -> KeepError {
    let detail = e.to_string();
    if detail.contains("Decryption failed") {
        KeepError::InvalidInput(format!(
            "Audit log integrity check FAILED: an entry could not be decrypted with the vault data key. This indicates tampering (entry rewritten or truncated mid-entry) or file corruption, NOT a wrong password. Details: {detail}"
        ))
    } else if detail.contains("audit line") || detail.contains("Invalid file format") {
        KeepError::InvalidInput(format!(
            "Audit log integrity check FAILED: an entry could not be parsed. This indicates tampering or file corruption. Details: {detail}"
        ))
    } else {
        e
    }
}

pub fn cmd_audit_retention(
    out: &Output,
    path: &Path,
    max_entries: Option<usize>,
    max_days: Option<u32>,
    apply: bool,
    hidden: bool,
) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let policy = RetentionPolicy {
        max_entries,
        max_age_days: max_days,
    };

    keep.audit_set_retention(policy);

    let has_policy_args = max_entries.is_some() || max_days.is_some();

    if apply {
        if !has_policy_args {
            return Err(keep_core::error::KeepError::InvalidInput(
                "audit retention --apply needs at least one of --max-entries or --max-days; pass a policy bound and try again".into(),
            ));
        }
        let removed = keep.audit_apply_retention()?;
        if removed > 0 {
            out.success(&format!("Removed {removed} old audit entries"));
        } else {
            out.info("No entries needed to be removed");
        }
    } else if has_policy_args {
        out.warn(
            "Retention policy parsed but NOT applied. This command is a one-shot prune control: it does NOT persist policy. Re-run with --apply to actually delete entries, or omit the flags to see this message.",
        );
    } else {
        return Err(keep_core::error::KeepError::InvalidInput(
            "audit retention is a one-shot prune control; it does NOT persist a policy across runs. Pass --max-entries and/or --max-days plus --apply to delete entries now.".into(),
        ));
    }

    Ok(())
}

#[derive(Default)]
struct AuditStats {
    key_gen: u32,
    key_import: u32,
    key_export: u32,
    key_delete: u32,
    sign_ok: u32,
    sign_fail: u32,
    frost_gen: u32,
    frost_sign_ok: u32,
    frost_sign_fail: u32,
    frost_session_start: u32,
    frost_share_import: u32,
    frost_share_export: u32,
    frost_share_delete: u32,
    frost_share_refresh: u32,
    auth_fail: u32,
    rate_limit_tripped: u32,
    unlock: u32,
    lock: u32,
}

impl AuditStats {
    fn record(&mut self, event_type: AuditEventType) {
        match event_type {
            AuditEventType::KeyGenerate => self.key_gen += 1,
            AuditEventType::KeyImport => self.key_import += 1,
            AuditEventType::KeyExport => self.key_export += 1,
            AuditEventType::KeyDelete => self.key_delete += 1,
            AuditEventType::Sign => self.sign_ok += 1,
            AuditEventType::SignFailed => self.sign_fail += 1,
            AuditEventType::FrostGenerate | AuditEventType::FrostSplit => self.frost_gen += 1,
            AuditEventType::FrostSign | AuditEventType::FrostSessionComplete => {
                self.frost_sign_ok += 1
            }
            AuditEventType::FrostSignFailed | AuditEventType::FrostSessionFailed => {
                self.frost_sign_fail += 1
            }
            AuditEventType::FrostSessionStart => self.frost_session_start += 1,
            AuditEventType::FrostShareImport => self.frost_share_import += 1,
            AuditEventType::FrostShareExport => self.frost_share_export += 1,
            AuditEventType::FrostShareDelete => self.frost_share_delete += 1,
            AuditEventType::FrostShareRefresh => self.frost_share_refresh += 1,
            AuditEventType::AuthFailed => self.auth_fail += 1,
            AuditEventType::RateLimitTripped => self.rate_limit_tripped += 1,
            AuditEventType::VaultUnlock => self.unlock += 1,
            AuditEventType::VaultLock => self.lock += 1,
        }
    }
}

pub fn cmd_audit_stats(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let entries = keep.audit_read_all()?;

    if entries.is_empty() {
        out.info("No audit entries found");
        return Ok(());
    }

    let mut stats = AuditStats::default();
    for entry in &entries {
        stats.record(entry.event_type);
    }

    let first_time = entries
        .first()
        .map(|e| format_timestamp(e.timestamp))
        .unwrap_or_default();
    let last_time = entries
        .last()
        .map(|e| format_timestamp(e.timestamp))
        .unwrap_or_default();

    out.info("Audit Log Statistics");
    out.info(&format!("Total entries: {}", entries.len()));
    out.info(&format!("First entry: {first_time}"));
    out.info(&format!("Last entry: {last_time}"));
    out.newline();
    out.info("Key Operations:");
    out.info(&format!("  Generated: {}", stats.key_gen));
    out.info(&format!("  Imported: {}", stats.key_import));
    out.info(&format!("  Exported: {}", stats.key_export));
    out.info(&format!("  Deleted: {}", stats.key_delete));
    out.newline();
    out.info("Signing:");
    out.info(&format!("  Successful: {}", stats.sign_ok));
    out.info(&format!("  Failed: {}", stats.sign_fail));
    out.newline();
    out.info("FROST Operations:");
    out.info(&format!("  Groups created: {}", stats.frost_gen));
    out.info(&format!(
        "  Sessions started: {}",
        stats.frost_session_start
    ));
    out.info(&format!("  Signatures (success): {}", stats.frost_sign_ok));
    out.info(&format!("  Signatures (failed): {}", stats.frost_sign_fail));
    out.newline();
    out.info("FROST Share Lifecycle:");
    out.info(&format!("  Imported: {}", stats.frost_share_import));
    out.info(&format!("  Exported: {}", stats.frost_share_export));
    out.info(&format!("  Deleted: {}", stats.frost_share_delete));
    out.info(&format!("  Refreshed: {}", stats.frost_share_refresh));
    out.newline();
    out.info("Security:");
    out.info(&format!("  Vault unlocks: {}", stats.unlock));
    out.info(&format!("  Vault locks: {}", stats.lock));
    out.info(&format!("  Auth failures: {}", stats.auth_fail));
    out.info(&format!("  Rate limit trips: {}", stats.rate_limit_tripped));

    Ok(())
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    /// Every `AuditEventType` variant must roll up into exactly one
    /// `AuditStats` counter. The match in `AuditStats::record` is now
    /// exhaustive (no `_ => {}` arm), so a new variant added to
    /// `AuditEventType` is a compile error here until the author decides
    /// which bucket it lands in.
    #[test]
    fn audit_stats_covers_every_event_type_variant() {
        let mut stats = AuditStats::default();
        stats.record(AuditEventType::KeyGenerate);
        stats.record(AuditEventType::KeyImport);
        stats.record(AuditEventType::KeyImport);
        stats.record(AuditEventType::KeyExport);
        stats.record(AuditEventType::KeyDelete);
        stats.record(AuditEventType::Sign);
        stats.record(AuditEventType::Sign);
        stats.record(AuditEventType::SignFailed);
        stats.record(AuditEventType::FrostGenerate);
        stats.record(AuditEventType::FrostSplit);
        stats.record(AuditEventType::FrostSign);
        stats.record(AuditEventType::FrostSessionComplete);
        stats.record(AuditEventType::FrostSignFailed);
        stats.record(AuditEventType::FrostSessionFailed);
        stats.record(AuditEventType::FrostSessionStart);
        stats.record(AuditEventType::FrostShareImport);
        stats.record(AuditEventType::FrostShareExport);
        stats.record(AuditEventType::FrostShareDelete);
        stats.record(AuditEventType::FrostShareRefresh);
        stats.record(AuditEventType::AuthFailed);
        stats.record(AuditEventType::RateLimitTripped);
        stats.record(AuditEventType::VaultUnlock);
        stats.record(AuditEventType::VaultLock);

        assert_eq!(stats.key_gen, 1);
        assert_eq!(stats.key_import, 2);
        assert_eq!(stats.key_export, 1);
        assert_eq!(stats.key_delete, 1);
        assert_eq!(stats.sign_ok, 2);
        assert_eq!(stats.sign_fail, 1);
        assert_eq!(stats.frost_gen, 2);
        assert_eq!(stats.frost_sign_ok, 2);
        assert_eq!(stats.frost_sign_fail, 2);
        assert_eq!(stats.frost_session_start, 1);
        assert_eq!(stats.frost_share_import, 1);
        assert_eq!(stats.frost_share_export, 1);
        assert_eq!(stats.frost_share_delete, 1);
        assert_eq!(stats.frost_share_refresh, 1);
        assert_eq!(stats.auth_fail, 1);
        assert_eq!(stats.rate_limit_tripped, 1);
        assert_eq!(stats.unlock, 1);
        assert_eq!(stats.lock, 1);
    }

    /// Closes the #526 gap surfaced by #441's testing pass: each of the
    /// previously-dropped variants now lands in a dedicated counter so
    /// `keep audit stats` actually surfaces lockouts and share-lifecycle
    /// events to the operator.
    #[test]
    fn audit_stats_surfaces_previously_dropped_security_variants() {
        let mut stats = AuditStats::default();
        stats.record(AuditEventType::RateLimitTripped);
        stats.record(AuditEventType::RateLimitTripped);
        stats.record(AuditEventType::VaultLock);
        stats.record(AuditEventType::FrostSessionStart);
        stats.record(AuditEventType::FrostShareImport);
        stats.record(AuditEventType::FrostShareExport);
        stats.record(AuditEventType::FrostShareDelete);
        stats.record(AuditEventType::FrostShareRefresh);

        assert_eq!(stats.rate_limit_tripped, 2);
        assert_eq!(stats.lock, 1);
        assert_eq!(stats.frost_session_start, 1);
        assert_eq!(stats.frost_share_import, 1);
        assert_eq!(stats.frost_share_export, 1);
        assert_eq!(stats.frost_share_delete, 1);
        assert_eq!(stats.frost_share_refresh, 1);
    }
}
