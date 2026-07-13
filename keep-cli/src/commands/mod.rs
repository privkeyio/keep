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
pub mod secret;
pub mod serve;
pub mod vault;
pub mod wallet;

use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use secrecy::{ExposeSecret, SecretString};
use tracing::debug;
use zeroize::Zeroizing;

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

/// Read a secret VALUE without ever taking it from `argv` (which leaks to shell
/// history and `ps`). Interactive stdin gets a hidden, no-echo prompt; a piped
/// stdin is read in full (so binary or multi-line values work), with a single
/// trailing newline stripped so `echo secret | keep secret add` stores `secret`,
/// not `secret\n` (use the interactive prompt or a file for exact bytes).
pub fn read_secret_value(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        let value = read_password(prompt)?;
        Ok(Zeroizing::new(value.into_bytes()))
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read secret value from stdin: {e}"
            )))
        })?;
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        Ok(buf)
    }
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

/// Minimum length for a duress credential. A crude entropy proxy: because the
/// pinned beacon pubkey is shared cluster-wide, a short credential is cheaply
/// grindable offline even behind Argon2id.
const MIN_DURESS_CREDENTIAL_LEN: usize = 12;

/// Read a DURESS credential (coercion resistance). Prompt + confirm, or the
/// `KEEP_DURESS_PASSWORD` env var , NEVER `KEEP_PASSWORD`, so an exported vault
/// password cannot silently become the duress trigger (which would make every
/// normal unlock fail closed). Refuses an empty/whitespace-only credential, and,
/// when `KEEP_PASSWORD` is also set, refuses a credential equal to it.
pub fn get_duress_credential(prompt: &str, confirm: &str) -> Result<SecretString> {
    let cred = if let Some(pw) = password_from_env("KEEP_DURESS_PASSWORD") {
        pw
    } else {
        let pw = Password::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .with_confirmation(confirm, "Credentials don't match")
            .interact()
            .map_err(|e| {
                KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                    "read password: {e}"
                )))
            })?;
        SecretString::from(pw)
    };
    let trimmed_len = cred.expose_secret().trim().chars().count();
    if trimmed_len == 0 {
        return Err(KeepError::invalid_input(
            "duress credential must not be empty",
        ));
    }
    // The pinned beacon pubkey is shared cluster-wide, so the duress credential is
    // offline-grindable if it leaks. Argon2id (HIGH) raises that cost, but a floor
    // on length is a cheap defense against a trivially short, low-entropy choice.
    if trimmed_len < MIN_DURESS_CREDENTIAL_LEN {
        return Err(KeepError::invalid_input(format!(
            "duress credential must be at least {MIN_DURESS_CREDENTIAL_LEN} characters \
             (its pinned pubkey is shared with the cluster and offline-grindable)"
        )));
    }
    if let Some(vault) = password_from_env("KEEP_PASSWORD") {
        if cred.expose_secret() == vault.expose_secret() {
            return Err(KeepError::invalid_input(
                "duress credential must be DISTINCT from the vault password (KEEP_PASSWORD)",
            ));
        }
    }
    Ok(cred)
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

/// Refuse to proceed unless the session is genuinely interactive.
///
/// `keep export` reveals raw private key material. Per the #467 decision, raw
/// private-key export is interactive-only by design: the threat model is
/// "operator accidentally automates" or "malware scripts the export". This is
/// a deliberate speed bump against accidental automation, not a hard control
/// against a local attacker who can drive a pty.
///
/// "Interactive" requires all three to hold:
///   - stdin is a TTY, so the operator can answer the prompts;
///   - stderr is a TTY, because the nsec is written to stderr (`Output` uses
///     `Term::stderr`), so gating only stdin would let `keep export 2>file`
///     redirect the secret sink while still passing the check; and
///   - no automation env vars (`KEEP_YES` / `KEEP_PASSWORD`) are set, since
///     those silently script past the password prompt and the "Display nsec?"
///     confirmation and would defeat the operator-in-the-loop intent.
///
/// The check fires BEFORE any password prompt or vault unlock so a missing TTY
/// surfaces immediately on the smallest possible attack surface.
pub fn require_interactive_tty(operation: &str) -> Result<()> {
    use std::io::IsTerminal;
    require_interactive(
        operation,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
        std::env::var_os("KEEP_YES").is_some() || std::env::var_os("KEEP_PASSWORD").is_some(),
    )
}

/// Pure policy behind [`require_interactive_tty`], split out so both the accept
/// and refuse branches are deterministically testable without depending on the
/// ambient TTY state of the test harness.
fn require_interactive(
    operation: &str,
    stdin_tty: bool,
    stderr_tty: bool,
    automation_env: bool,
) -> Result<()> {
    if stdin_tty && stderr_tty && !automation_env {
        return Ok(());
    }
    Err(KeepError::InvalidInput(format!(
        "{operation} is interactive-only by design: it refuses to run unless stdin and stderr are both a TTY \
         and no automation env vars (KEEP_YES / KEEP_PASSWORD) are set. Raw private-key export reveals secret \
         material; running it from a script, a pipe, or with the secret stream redirected defeats the \
         operator-in-the-loop intent. If you genuinely need to automate this, wrap the command in `expect` / a \
         pty harness; see #467 for the policy rationale."
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

    fn assert_refusal(err: &KeepError, operation: &str) {
        let msg = err.to_string();
        assert!(
            matches!(err, KeepError::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );
        assert!(
            msg.contains(operation),
            "error must name the operation: {msg}"
        );
        assert!(
            msg.contains("interactive-only") && msg.contains("#467"),
            "error must explain why and point at the policy issue: {msg}"
        );
    }

    /// A genuinely interactive session (TTY in + TTY out, no automation env)
    /// is the only combination that is allowed through.
    #[test]
    fn require_interactive_accepts_full_interactive_session() {
        require_interactive("keep export", true, true, false)
            .expect("tty stdin + tty stderr with no automation env must be allowed");
    }

    #[test]
    fn require_interactive_refuses_non_tty_stdin() {
        let err = require_interactive("keep export", false, true, false).unwrap_err();
        assert_refusal(&err, "keep export");
    }

    /// The nsec is written to stderr, so redirecting the secret sink
    /// (`keep export 2>file`) must be refused even when stdin is still a TTY.
    #[test]
    fn require_interactive_refuses_non_tty_stderr() {
        let err = require_interactive("keep export", true, false, false).unwrap_err();
        assert_refusal(&err, "keep export");
    }

    /// `KEEP_YES` / `KEEP_PASSWORD` would script past the prompt and confirm,
    /// so their presence is treated as non-interactive.
    #[test]
    fn require_interactive_refuses_automation_env() {
        let err = require_interactive("keep export", true, true, true).unwrap_err();
        assert_refusal(&err, "keep export");
    }
}
