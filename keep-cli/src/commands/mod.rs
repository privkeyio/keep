// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

pub mod agent;
pub mod audit;
pub mod bitcoin;
pub mod enclave;
pub mod frost;
pub mod frost_hardware;
pub mod frost_network;
pub mod migrate;
pub mod nip46;
pub mod serve;
pub mod vault;
pub mod wallet;

use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use secrecy::SecretString;
use tracing::debug;

use keep_core::error::{KeepError, Result};

fn warn_env_password(var_name: &str) {
    tracing::warn!(
        "Using password from {} environment variable. \
         Environment variables may be visible to other processes via /proc on Linux.",
        var_name
    );
}

fn password_from_env(var_name: &str) -> Option<SecretString> {
    std::env::var(var_name).ok().map(|pw| {
        debug!("using password from {} env var", var_name);
        warn_env_password(var_name);
        SecretString::from(pw)
    })
}

fn read_password(prompt: &str) -> Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read password: {e}"
            )))
        })
}

pub fn get_password(prompt: &str) -> Result<SecretString> {
    if let Some(pw) = password_from_env("KEEP_PASSWORD") {
        return Ok(pw);
    }
    read_password(prompt).map(SecretString::from)
}

pub fn get_hidden_password(prompt: &str) -> Result<SecretString> {
    if let Some(pw) = password_from_env("KEEP_HIDDEN_PASSWORD") {
        return Ok(pw);
    }
    read_password(prompt).map(SecretString::from)
}

pub fn get_password_with_confirm(prompt: &str, confirm: &str) -> Result<SecretString> {
    if let Some(pw) = password_from_env("KEEP_PASSWORD") {
        return Ok(pw);
    }
    let pw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .with_confirmation(confirm, "Passwords don't match")
        .interact()
        .map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read password: {e}"
            )))
        })?;
    Ok(SecretString::from(pw))
}

pub fn get_new_password_with_confirm(prompt: &str, confirm: &str) -> Result<SecretString> {
    if let Some(pw) = password_from_env("KEEP_NEW_PASSWORD") {
        return Ok(pw);
    }
    let pw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .with_confirmation(confirm, "Passwords don't match")
        .interact()
        .map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read password: {e}"
            )))
        })?;
    Ok(SecretString::from(pw))
}

/// Refuse to proceed when stdin is not a TTY.
///
/// `keep export` reveals raw private key material. Per the #467 decision, raw
/// private-key export is interactive-only by design: the threat model is
/// exactly "operator accidentally automates" or "malware scripts the export",
/// and an env-var or `--yes` gate barely raises the bar against either.
/// Operators who genuinely need scripted export can wrap in `expect`/`pty`;
/// the speed bump is intentional. The check fires BEFORE any password prompt
/// or vault unlock so a missing TTY surfaces immediately on the smallest
/// possible attack surface.
pub fn require_interactive_tty(operation: &str) -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    Err(KeepError::InvalidInput(format!(
        "{operation} is interactive-only by design: stdin is not a TTY, so this command refuses to run. \
         Raw private-key export reveals secret material; running it from a script or pipe defeats the operator-in-the-loop \
         intent. If you genuinely need to automate this, wrap the command in `expect` / a pty harness; see #467 for the \
         policy rationale."
    )))
}

pub fn get_confirm(prompt: &str) -> Result<bool> {
    if std::env::var("KEEP_YES").is_ok() {
        return Ok(true);
    }
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read confirmation: {e}"
            )))
        })
}

pub fn get_nsec(prompt: &str) -> Result<SecretString> {
    if let Ok(nsec) = std::env::var("KEEP_NSEC") {
        debug!("using nsec from KEEP_NSEC env var");
        return Ok(SecretString::from(nsec));
    }
    let nsec = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read nsec: {e}"
            )))
        })?;
    Ok(SecretString::from(nsec))
}

pub fn is_hidden_vault(path: &std::path::Path) -> bool {
    path.join("keep.vault").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `require_interactive_tty` must return an `InvalidInput` error whose
    /// message names the operation and points at #467 when stdin is not a
    /// TTY. In the test harness stdin is never a TTY, so this is a stable
    /// negative-path assertion.
    #[test]
    fn require_interactive_tty_rejects_non_tty_stdin() {
        let err = require_interactive_tty("keep export")
            .expect_err("test harness stdin is not a TTY; require_interactive_tty must refuse");
        let msg = err.to_string();
        assert!(
            matches!(err, KeepError::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );
        assert!(
            msg.contains("keep export"),
            "error must name the operation: {msg}"
        );
        assert!(
            msg.contains("interactive-only") && msg.contains("#467"),
            "error must explain why and point at the policy issue: {msg}"
        );
    }
}
