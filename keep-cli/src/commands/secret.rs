// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! `keep secret` subcommands: store, reveal, list, and remove arbitrary secrets
//! (passwords, API tokens, notes) in the vault. Thin surface over the keep-core
//! secrets store (`Keep::store_secret`/`load_secret`/`list_secrets`/
//! `delete_secret`); the value never passes through `argv`.

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::{debug, warn};

use keep_core::error::{KeepError, Result};
use keep_core::secret::SecretRecord;
use keep_core::Keep;

use crate::cli::SecretKindArg;
use crate::output::Output;

use super::{
    get_confirm, get_password, is_hidden_vault, read_secret_value, require_interactive_tty,
};

/// Upper bound on a secret's title length; a crude guard against a runaway name.
const MAX_SECRET_NAME_LEN: usize = 128;

/// Secrets live only in the standard vault for now. The hidden-volume subsystem
/// stores its rows through a separate code path with no secrets table, so refuse
/// loudly rather than silently operate on the wrong vault.
fn refuse_hidden(path: &Path, hidden: bool) -> Result<()> {
    if hidden || is_hidden_vault(path) {
        return Err(KeepError::invalid_input(
            "the secrets store is not yet available in hidden volumes; use a standard vault",
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(KeepError::invalid_input("secret name must not be empty"));
    }
    if name.chars().count() > MAX_SECRET_NAME_LEN {
        return Err(KeepError::invalid_input(format!(
            "secret name must be at most {MAX_SECRET_NAME_LEN} characters"
        )));
    }
    Ok(())
}

fn open_unlock(out: &Output, path: &Path) -> Result<Keep> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;
    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();
    Ok(keep)
}

/// Resolve a `name`-or-`id-prefix` argument to exactly one stored secret. Names
/// are the primary handle; because a secret's id is random, two entries may share
/// a name, so a hex id prefix (from `list`) disambiguates. Errors when the handle
/// is missing or still ambiguous, listing the candidate id prefixes.
fn resolve_secret(keep: &Keep, handle: &str) -> Result<SecretRecord> {
    let secrets = keep.list_secrets()?;
    resolve_in(&secrets, handle).cloned()
}

/// Pure resolution behind [`resolve_secret`], split out so its branches are
/// testable without a vault. Names are tried first; a hex id prefix is the
/// fallback that disambiguates same-named entries.
fn resolve_in<'a>(secrets: &'a [SecretRecord], handle: &str) -> Result<&'a SecretRecord> {
    let by_name: Vec<&SecretRecord> = secrets.iter().filter(|s| s.name == handle).collect();
    match by_name.len() {
        1 => return Ok(by_name[0]),
        n if n > 1 => {
            let prefixes: Vec<String> = by_name
                .iter()
                .map(|s| hex::encode(s.id)[..12].to_string())
                .collect();
            return Err(KeepError::invalid_input(format!(
                "{n} secrets named '{handle}'; re-run with one of these id prefixes: {}",
                prefixes.join(", ")
            )));
        }
        _ => {}
    }

    let handle_lc = handle.to_ascii_lowercase();
    if handle.len() >= 4 && handle.chars().all(|c| c.is_ascii_hexdigit()) {
        let by_id: Vec<&SecretRecord> = secrets
            .iter()
            .filter(|s| hex::encode(s.id).starts_with(&handle_lc))
            .collect();
        match by_id.len() {
            1 => return Ok(by_id[0]),
            n if n > 1 => {
                return Err(KeepError::invalid_input(format!(
                    "id prefix '{handle}' matches {n} secrets; use a longer prefix"
                )))
            }
            _ => {}
        }
    }

    Err(KeepError::NotFound(format!(
        "no secret matching '{handle}'"
    )))
}

pub fn cmd_secret_add(
    out: &Output,
    path: &Path,
    name: &str,
    kind: SecretKindArg,
    hidden: bool,
) -> Result<()> {
    refuse_hidden(path, hidden)?;
    validate_name(name)?;

    // Read the value off a hidden prompt or piped stdin, never argv.
    let value = read_secret_value("Secret value")?;
    if value.is_empty() {
        return Err(KeepError::invalid_input("secret value must not be empty"));
    }

    let mut keep = open_unlock(out, path)?;
    let kind_core: keep_core::secret::SecretKind = kind.into();
    let record = SecretRecord::new(name.to_string(), kind_core, value.to_vec())?;
    keep.store_secret(&record)?;

    out.success(&format!(
        "Stored secret '{}' ({:?}); id {}",
        name,
        kind_core,
        hex::encode(record.id)
    ));
    Ok(())
}

pub fn cmd_secret_get(out: &Output, path: &Path, handle: &str, hidden: bool) -> Result<()> {
    // Revealing a secret value is interactive-only by design, matching `export`:
    // fail fast before any password prompt or vault unlock.
    require_interactive_tty("keep secret get")?;
    refuse_hidden(path, hidden)?;

    let keep = open_unlock(out, path)?;
    let record = resolve_secret(&keep, handle)?;

    out.secret_warning();
    out.newline();
    if get_confirm("Display secret value?")? {
        warn!(id = %hex::encode(record.id), "secret value revealed");
        out.newline();
        match std::str::from_utf8(&record.value) {
            Ok(s) => out.info(s),
            Err(_) => out.info(&format!("(binary; hex) {}", hex::encode(&record.value))),
        }
    }
    Ok(())
}

pub fn cmd_secret_list(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    refuse_hidden(path, hidden)?;
    debug!("listing secrets");

    let keep = open_unlock(out, path)?;
    let mut secrets = keep.list_secrets()?;
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    if secrets.is_empty() {
        out.newline();
        out.info("No secrets stored. Use 'keep secret add' to store one.");
        return Ok(());
    }

    out.table_header(&[("NAME", 28), ("KIND", 10), ("ID (prefix)", 16)]);
    for s in &secrets {
        out.table_row(&[
            (&s.name, 28, false),
            (&format!("{:?}", s.kind), 10, false),
            (&hex::encode(s.id)[..12], 16, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} secret(s) total", secrets.len()));
    Ok(())
}

pub fn cmd_secret_rm(out: &Output, path: &Path, handle: &str, hidden: bool) -> Result<()> {
    refuse_hidden(path, hidden)?;

    let mut keep = open_unlock(out, path)?;
    let record = resolve_secret(&keep, handle)?;
    let id = record.id;
    let name = record.name.clone();
    keep.delete_secret(&id)?;

    out.success(&format!("Removed secret '{name}' (id {})", hex::encode(id)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::secret::SecretKind;

    fn rec(name: &str, id: [u8; 32]) -> SecretRecord {
        SecretRecord {
            id,
            name: name.to_string(),
            kind: SecretKind::Generic,
            value: Vec::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn validate_name_rejects_empty_and_overlong() {
        assert!(validate_name("ok").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_SECRET_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn resolve_prefers_unique_name() {
        let secrets = vec![rec("github", [1u8; 32]), rec("api", [2u8; 32])];
        assert_eq!(resolve_in(&secrets, "github").unwrap().id, [1u8; 32]);
    }

    #[test]
    fn resolve_duplicate_name_is_ambiguous() {
        let secrets = vec![rec("dup", [1u8; 32]), rec("dup", [2u8; 32])];
        assert!(resolve_in(&secrets, "dup").is_err());
    }

    #[test]
    fn resolve_by_id_prefix() {
        let mut a = [0u8; 32];
        a[0] = 0xab;
        let mut b = [0u8; 32];
        b[0] = 0xcd;
        let secrets = vec![rec("dup", a), rec("dup", b)];
        // A hex prefix unique to `a` resolves even though the name is duplicated.
        assert_eq!(resolve_in(&secrets, "ab00").unwrap().id, a);
    }

    #[test]
    fn resolve_missing_handle_errors() {
        let secrets = vec![rec("github", [1u8; 32])];
        assert!(resolve_in(&secrets, "nope").is_err());
    }
}
