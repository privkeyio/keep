#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use secrecy::ExposeSecret;

use keep_core::audit::{AuditEventType, RetentionPolicy};
use keep_core::error::Result;
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
            details.push(format!("t:{}", t));
        }
        if let Some(ref reason) = entry.reason {
            details.push(format!("reason:{}", reason));
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
        None => println!("{}", json),
    }

    Ok(())
}

pub fn cmd_audit_verify(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    let mut keep = Keep::open(&resolve_path(path, hidden))?;
    let password = get_password("Password")?;
    keep.unlock(password.expose_secret())?;

    let valid = keep.audit_verify_chain()?;

    if valid {
        out.success("Audit log integrity verified - hash chain is valid");
    } else {
        out.error("Audit log integrity check FAILED - hash chain is broken");
        std::process::exit(1);
    }

    Ok(())
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

    if apply {
        let removed = keep.audit_apply_retention()?;
        if removed > 0 {
            out.success(&format!("Removed {} old audit entries", removed));
        } else {
            out.info("No entries needed to be removed");
        }
    } else {
        out.info("Retention policy set (use --apply to remove old entries)");
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
    auth_fail: u32,
    unlock: u32,
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
            AuditEventType::AuthFailed => self.auth_fail += 1,
            AuditEventType::VaultUnlock => self.unlock += 1,
            _ => {}
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
    out.info(&format!("First entry: {}", first_time));
    out.info(&format!("Last entry: {}", last_time));
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
    out.info(&format!("  Signatures (success): {}", stats.frost_sign_ok));
    out.info(&format!("  Signatures (failed): {}", stats.frost_sign_fail));
    out.newline();
    out.info("Security:");
    out.info(&format!("  Vault unlocks: {}", stats.unlock));
    out.info(&format!("  Auth failures: {}", stats.auth_fail));

    Ok(())
}
