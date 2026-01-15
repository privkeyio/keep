// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use dialoguer::{theme::ColorfulTheme, Password};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use keep_core::crypto::Argon2Params;
use keep_core::error::{KeepError, Result};
use keep_core::keys::bytes_to_npub;
use keep_core::Keep;

use crate::output::Output;

use super::{get_confirm, get_hidden_password, get_nsec, get_password, get_password_with_confirm, is_hidden_vault};

pub fn cmd_init(out: &Output, path: &Path, hidden: bool, size_mb: u64) -> Result<()> {
    if hidden {
        out.hidden_banner();
    }

    out.header("Creating new Keep");
    out.field("Path", &path.display().to_string());
    out.newline();

    let (outer_prompt, outer_confirm) = if hidden {
        ("Enter OUTER password", "Confirm OUTER password")
    } else {
        ("Enter password", "Confirm password")
    };

    let outer_password = get_password_with_confirm(outer_prompt, outer_confirm)?;

    if outer_password.expose_secret().len() < 8 {
        return Err(KeepError::Other(
            "Password must be at least 8 characters".into(),
        ));
    }

    let hidden_password: Option<SecretString> = if hidden {
        out.newline();
        let hp = if let Ok(hp_env) = std::env::var("KEEP_HIDDEN_PASSWORD") {
            debug!("using hidden password from KEEP_HIDDEN_PASSWORD env var");
            SecretString::from(hp_env)
        } else {
            let pw = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter HIDDEN password (must be different!)")
                .with_confirmation("Confirm HIDDEN password", "Passwords don't match")
                .interact()
                .map_err(|e| KeepError::Other(format!("Failed to read password: {}", e)))?;
            SecretString::from(pw)
        };

        if hp.expose_secret() == outer_password.expose_secret() {
            return Err(KeepError::Other(
                "HIDDEN password must be DIFFERENT from OUTER password!".into(),
            ));
        }

        if hp.expose_secret().len() < 8 {
            return Err(KeepError::Other(
                "Password must be at least 8 characters".into(),
            ));
        }

        Some(hp)
    } else {
        None
    };

    let spinner = out.spinner("Deriving keys and creating volume...");
    let total_size = size_mb * 1024 * 1024;

    info!(size_mb, hidden, "creating keep");

    let params = if std::env::var("KEEP_TESTING_MODE").is_ok() {
        debug!("using lightweight Argon2 params (KEEP_TESTING_MODE set)");
        Argon2Params::TESTING
    } else {
        Argon2Params::DEFAULT
    };

    if hidden {
        keep_core::hidden::HiddenStorage::create(
            path,
            outer_password.expose_secret(),
            hidden_password.as_ref().map(|s| s.expose_secret()),
            total_size,
            0.2,
            params,
        )?;
    } else {
        Keep::create_with_params(path, outer_password.expose_secret(), params)?;
    }

    spinner.finish();
    out.newline();
    out.success("Keep created successfully!");

    if hidden {
        out.hidden_notes();
    } else {
        out.init_notes();
    }

    Ok(())
}

pub fn cmd_generate(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_generate_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_generate_outer(out, path, name);
    }

    debug!(name, "generating key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let pubkey = keep.generate_key(name)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated");

    out.newline();
    out.success("Generated new key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_generate_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated in outer volume");

    out.newline();
    out.success("Generated new key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_generate_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated in hidden volume");

    out.newline();
    out.success("Generated new key in hidden volume!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

pub fn cmd_import(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_import_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_import_outer(out, path, name);
    }

    debug!(name, "importing key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let nsec = get_nsec("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let pubkey = keep.import_nsec(nsec.expose_secret(), name)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported");

    out.newline();
    out.success("Imported key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let nsec = get_nsec("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(nsec.expose_secret())?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported to outer volume");

    out.newline();
    out.success("Imported key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let nsec = get_nsec("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(nsec.expose_secret())?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported to hidden volume");

    out.newline();
    out.success("Imported key to hidden volume!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

pub fn cmd_list(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_list_hidden(out, path);
    }
    if is_hidden_vault(path) {
        return cmd_list_outer(out, path);
    }

    debug!("listing keys");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let keys = keep.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found. Use 'keep generate' to create one.");
        return Ok(());
    }

    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

fn cmd_list_outer(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!("listing keys in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found. Use 'keep generate' to create one.");
        return Ok(());
    }

    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

fn cmd_list_hidden(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!("listing keys in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found in hidden volume. Use 'keep --hidden generate' to create one.");
        return Ok(());
    }

    out.hidden_label();
    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

pub fn cmd_export(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_export_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_export_outer(out, path, name);
    }

    debug!(name, "exporting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let keypair = slot.to_nostr_keypair()?;

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::NostrKeypair;

    debug!(name, "exporting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
    let secret_bytes = crypto::decrypt(&encrypted, data_key)?;

    let mut secret = [0u8; 32];
    let decrypted = secret_bytes.as_slice()?;
    secret.copy_from_slice(&decrypted);
    let keypair = NostrKeypair::from_secret_bytes(&mut secret);
    secret.zeroize();
    let keypair = keypair?;

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported from outer volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::NostrKeypair;

    debug!(name, "exporting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
    let secret_bytes = crypto::decrypt(&encrypted, data_key)?;

    let mut secret = [0u8; 32];
    let decrypted = secret_bytes.as_slice()?;
    secret.copy_from_slice(&decrypted);
    let keypair = NostrKeypair::from_secret_bytes(&mut secret);
    secret.zeroize();
    let keypair = keypair?;

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported from hidden volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

pub fn cmd_delete(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_delete_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_delete_outer(out, path, name);
    }

    debug!(name, "deleting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let pubkey = slot.pubkey;

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name))? {
        out.info("Cancelled.");
        return Ok(());
    }

    keep.delete_key(&pubkey)?;
    info!(name, "key deleted");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;

    debug!(name, "deleting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let id = crypto::blake2b_256(&record.pubkey);

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name))? {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from outer volume");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;

    debug!(name, "deleting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let id = crypto::blake2b_256(&record.pubkey);

    if !get_confirm(&format!(
        "Delete key '{}' from hidden volume? This cannot be undone!",
        name
    ))? {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from hidden volume");

    out.newline();
    out.success(&format!("Deleted key from hidden volume: {}", name));

    Ok(())
}
