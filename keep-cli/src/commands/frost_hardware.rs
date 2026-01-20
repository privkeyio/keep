// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;
use crate::signer::HardwareSigner;

use super::{get_confirm, get_password};

pub fn cmd_frost_hardware_ping(out: &Output, device: &str) -> Result<()> {
    out.newline();
    out.header("Hardware Signer Ping");
    out.field("Device", device);
    out.newline();

    let spinner = out.spinner("Connecting to hardware signer...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Sending ping...");
    let version = signer
        .ping()
        .map_err(|e| KeepError::Other(format!("Ping failed: {}", e)))?;
    spinner.finish();

    out.success(&format!("Hardware signer v{} - OK", version));
    Ok(())
}

pub fn cmd_frost_hardware_list(out: &Output, device: &str) -> Result<()> {
    out.newline();
    out.header("Hardware Signer Shares");
    out.field("Device", device);
    out.newline();

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Listing shares...");
    let shares = signer
        .list_shares()
        .map_err(|e| KeepError::Other(format!("List failed: {}", e)))?;
    spinner.finish();

    if shares.is_empty() {
        out.info("No shares stored on hardware");
    } else {
        out.info(&format!("Found {} share(s):", shares.len()));
        for share in shares {
            out.field("  Group", &share);
        }
    }
    Ok(())
}

pub fn cmd_frost_hardware_import(
    out: &Output,
    path: &Path,
    device: &str,
    group_npub: &str,
    share_index: u16,
) -> Result<()> {
    use crate::signer::hardware::serialize_share_for_hardware;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let stored_share = keep.frost_get_share_by_index(&group_pubkey, share_index)?;

    out.newline();
    out.header("Hardware Import");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.field(
        "Share",
        &format!(
            "{} ({})",
            stored_share.metadata.identifier, stored_share.metadata.name
        ),
    );
    out.field(
        "Threshold",
        &format!(
            "{}-of-{}",
            stored_share.metadata.threshold, stored_share.metadata.total_shares
        ),
    );
    out.newline();

    let key_package = stored_share.key_package()?;
    let pubkey_package = stored_share.pubkey_package()?;

    let secret_share = key_package.signing_share();
    let verifying_share = key_package.verifying_share();

    let secret_serialized = secret_share.serialize();
    let secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        secret_serialized
            .as_slice()
            .try_into()
            .map_err(|_| KeepError::Frost("Invalid secret share length".into()))?,
    );

    let verifying_share_bytes = verifying_share
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying share: {}", e)))?;
    let mut pubkey_compressed = [0u8; 33];
    pubkey_compressed.copy_from_slice(&verifying_share_bytes);

    let group_vk = pubkey_package.verifying_key();
    let group_vk_bytes = group_vk
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize group key: {}", e)))?;
    let mut group_pubkey_compressed = [0u8; 33];
    group_pubkey_compressed.copy_from_slice(&group_vk_bytes);

    let hardware_share: Zeroizing<Vec<u8>> = Zeroizing::new(serialize_share_for_hardware(
        &secret_bytes,
        &pubkey_compressed,
        &group_pubkey_compressed,
        stored_share.metadata.identifier,
        stored_share.metadata.total_shares,
        stored_share.metadata.threshold,
    ));

    let share_hex: Zeroizing<String> = Zeroizing::new(hex::encode(&*hardware_share));

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer
        .ping()
        .map_err(|e| KeepError::Other(format!("Ping failed: {}", e)))?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Importing share to hardware...");
    signer
        .import_share(group_npub, &share_hex)
        .map_err(|e| KeepError::Other(format!("Import failed: {}", e)))?;
    spinner.finish();

    out.success("Share imported successfully");
    out.info("The share is now stored on the hardware device.");
    out.info("You can safely delete the share from this machine.");
    Ok(())
}

pub fn cmd_frost_hardware_delete(out: &Output, device: &str, group_npub: &str) -> Result<()> {
    out.newline();
    out.header("Hardware Delete Share");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.newline();

    if !get_confirm("Delete share from hardware? This cannot be undone.")? {
        out.info("Cancelled");
        return Ok(());
    }

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Deleting share...");
    signer
        .delete_share(group_npub)
        .map_err(|e| KeepError::Other(format!("Delete failed: {}", e)))?;
    spinner.finish();

    out.success("Share deleted from hardware");
    Ok(())
}

pub fn cmd_frost_hardware_sign(
    out: &Output,
    device: &str,
    group_npub: &str,
    session_id_hex: &str,
    commitments_hex: &str,
) -> Result<()> {
    let session_id_bytes = hex::decode(session_id_hex)
        .map_err(|_| KeepError::Other("Invalid session_id hex".into()))?;
    if session_id_bytes.len() != 32 {
        return Err(KeepError::Other("session_id must be 32 bytes".into()));
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&session_id_bytes);

    out.newline();
    out.header("FROST Hardware Sign (Round 2)");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.field("Session ID", session_id_hex);
    out.newline();

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Generating signature share...");
    let (sig_share, index) = signer
        .frost_sign(group_npub, &session_id, commitments_hex)
        .map_err(|e| KeepError::Other(format!("Sign failed: {}", e)))?;
    spinner.finish();

    out.field("Share index", &index.to_string());
    out.field("Signature share", &hex::encode(&sig_share));
    out.success("Round 2 complete");
    Ok(())
}

pub fn cmd_frost_hardware_export(
    out: &Output,
    device: &str,
    group_npub: &str,
    output_file: Option<&str>,
) -> Result<()> {
    use secrecy::ExposeSecret;
    use std::io::Write;

    out.newline();
    out.header("Hardware Share Export");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.newline();

    out.warn("This exports your encrypted share for backup purposes.");
    out.warn("The passphrase you enter will be used to encrypt the export.");
    out.newline();

    if !get_confirm("Export share from hardware?")? {
        out.info("Cancelled");
        return Ok(());
    }

    let passphrase = get_password("Enter export passphrase (min 8 chars)")?;
    if passphrase.expose_secret().len() < 8 {
        return Err(KeepError::Other("Passphrase must be at least 8 characters".into()));
    }

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Exporting share...");
    let exported = signer
        .export_share(group_npub, passphrase.expose_secret())
        .map_err(|e| KeepError::Other(format!("Export failed: {}", e)))?;
    spinner.finish();

    let export_json = serde_json::json!({
        "version": exported.version,
        "group": exported.group,
        "share_index": exported.share_index,
        "threshold": exported.threshold,
        "participants": exported.participants,
        "group_pubkey": exported.group_pubkey,
        "encrypted_share": exported.encrypted_share,
        "nonce": exported.nonce,
        "salt": exported.salt,
        "checksum": exported.checksum,
    });

    if let Some(path) = output_file {
        let mut file = std::fs::File::create(path)
            .map_err(|e| KeepError::Other(format!("Failed to create file: {}", e)))?;
        file.write_all(serde_json::to_string_pretty(&export_json).unwrap().as_bytes())
            .map_err(|e| KeepError::Other(format!("Failed to write file: {}", e)))?;
        out.success(&format!("Share exported to {}", path));
    } else {
        out.newline();
        println!("{}", serde_json::to_string_pretty(&export_json).unwrap());
    }

    out.newline();
    out.field("Share index", &exported.share_index.to_string());
    out.field(
        "Threshold",
        &format!("{}-of-{}", exported.threshold, exported.participants),
    );
    out.success("Export complete");
    Ok(())
}
