// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod agent;
pub mod audit;
pub mod bitcoin;
pub mod enclave;
pub mod frost;
pub mod frost_hardware;
pub mod frost_network;
pub mod serve;
pub mod vault;

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
        .map_err(|e| KeepError::Other(format!("Failed to read password: {}", e)))
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
        .map_err(|e| KeepError::Other(format!("Failed to read password: {}", e)))?;
    Ok(SecretString::from(pw))
}

pub fn get_confirm(prompt: &str) -> Result<bool> {
    if std::env::var("KEEP_YES").is_ok() {
        return Ok(true);
    }
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|e| KeepError::Other(format!("Failed to read confirmation: {}", e)))
}

pub fn get_nsec(prompt: &str) -> Result<SecretString> {
    if let Ok(nsec) = std::env::var("KEEP_NSEC") {
        debug!("using nsec from KEEP_NSEC env var");
        return Ok(SecretString::from(nsec));
    }
    let nsec = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .map_err(|e| KeepError::Other(format!("Failed to read nsec: {}", e)))?;
    Ok(SecretString::from(nsec))
}

pub fn is_hidden_vault(path: &std::path::Path) -> bool {
    path.join("keep.vault").exists()
}
