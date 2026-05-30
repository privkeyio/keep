// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;
use crate::signer::HardwareSigner;

use super::{get_confirm, get_password, get_password_with_confirm};

pub fn cmd_frost_hardware_ping(out: &Output, device: &str) -> Result<()> {
    out.newline();
    out.header("Hardware Signer Ping");
    out.field("Device", device);
    out.newline();

    let spinner = out.spinner("Connecting to hardware signer...");
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Sending ping...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware ping: {e}"
        )))
    })?;
    spinner.finish();

    out.success(&format!("Hardware signer v{version} - OK"));
    Ok(())
}

pub fn cmd_frost_hardware_list(out: &Output, device: Option<&str>) -> Result<()> {
    match device {
        Some(d) => list_one(out, d),
        None => enumerate_and_list(out),
    }
}

fn list_one(out: &Output, device: &str) -> Result<()> {
    out.newline();
    out.header("Hardware Signer Shares");
    out.field("Device", device);
    out.newline();

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Listing shares...");
    let shares = signer.list_shares().map_err(|e| {
        KeepError::FrostErr(keep_core::error::FrostError::session(format!(
            "list shares: {e}"
        )))
    })?;
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

fn enumerate_and_list(out: &Output) -> Result<()> {
    use std::time::Duration;

    // Short per-probe timeout so a stuck or non-keep serial device fails fast
    // rather than blocking the entire scan ~30s. The default constructor's 30s
    // timeout is still used by `cmd_frost_hardware_list` (single-device path)
    // and by other hardware commands.
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

    out.newline();
    out.header("Hardware Signer Devices");
    out.newline();

    let candidates = candidate_serial_devices();
    if candidates.is_empty() {
        out.info("No candidate serial devices found (looked for /dev/ttyACM*, /dev/ttyUSB*, /dev/cu.usbmodem*).");
        return Ok(());
    }

    let mut found = 0usize;
    for candidate in &candidates {
        out.field("Probing", candidate);
        match HardwareSigner::with_timeout(candidate, PROBE_TIMEOUT) {
            Ok(mut signer) => match signer.ping() {
                Ok(version) => {
                    found += 1;
                    out.field("  Version", &version);
                    match signer.list_shares() {
                        Ok(shares) => {
                            if shares.is_empty() {
                                out.info("  No shares stored");
                            } else {
                                out.info(&format!("  {} share(s):", shares.len()));
                                for share in shares {
                                    out.field("    Group", &share);
                                }
                            }
                        }
                        Err(e) => out.info(&format!("  Could not list shares on {candidate}: {e}")),
                    }
                }
                Err(e) => out.info(&format!("  Not a keep hardware signer: {e}")),
            },
            Err(e) => out.info(&format!("  Cannot open: {e}")),
        }
    }
    out.newline();
    out.info(&format!(
        "{} keep hardware signer(s) responded out of {} candidate(s).",
        found,
        candidates.len()
    ));
    Ok(())
}

fn candidate_serial_devices() -> Vec<String> {
    let mut out = Vec::new();
    for pattern in ["/dev/ttyACM", "/dev/ttyUSB", "/dev/cu.usbmodem"] {
        let dir = std::path::Path::new(pattern)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/dev"));
        let prefix = std::path::Path::new(pattern)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                if name_str.starts_with(prefix) {
                    if let Some(p) = entry.path().to_str() {
                        out.push(p.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
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
        .map_err(|e| KeepError::Frost(format!("Failed to serialize verifying share: {e}")))?;
    let mut pubkey_compressed = [0u8; 33];
    pubkey_compressed.copy_from_slice(&verifying_share_bytes);

    let group_vk = pubkey_package.verifying_key();
    let group_vk_bytes = group_vk
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Failed to serialize group key: {e}")))?;
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
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware ping: {e}"
        )))
    })?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Importing share to hardware...");
    signer.import_share(group_npub, &share_hex).map_err(|e| {
        KeepError::FrostErr(keep_core::error::FrostError::invalid_share(format!(
            "import: {e}"
        )))
    })?;
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
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Deleting share...");
    signer.delete_share(group_npub).map_err(|e| {
        KeepError::FrostErr(keep_core::error::FrostError::session(format!(
            "delete: {e}"
        )))
    })?;
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
        .map_err(|_| KeepError::InvalidInput("invalid session_id hex".into()))?;
    if session_id_bytes.len() != 32 {
        return Err(KeepError::InvalidInput(
            "session_id must be 32 bytes".into(),
        ));
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
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Generating signature share...");
    let (sig_share, index) = signer
        .frost_sign(group_npub, &session_id, commitments_hex)
        .map_err(|e| {
            KeepError::FrostErr(keep_core::error::FrostError::session(format!("sign: {e}")))
        })?;
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

    let passphrase = get_password_with_confirm(
        "Enter export passphrase (min 8 chars)",
        "Confirm passphrase",
    )?;
    if passphrase.expose_secret().len() < 8 {
        return Err(KeepError::InvalidInput(
            "passphrase must be at least 8 characters".into(),
        ));
    }

    let spinner = out.spinner("Connecting...");
    let mut signer = HardwareSigner::new(device).map_err(|e| {
        KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
            "hardware: {e}"
        )))
    })?;
    spinner.finish();

    let spinner = out.spinner("Exporting share...");
    let exported = signer
        .export_share(group_npub, passphrase.expose_secret())
        .map_err(|e| {
            KeepError::FrostErr(keep_core::error::FrostError::session(format!(
                "export: {e}"
            )))
        })?;
    spinner.finish();

    let json_str = serde_json::to_string_pretty(&exported).map_err(|e| {
        KeepError::StorageErr(keep_core::error::StorageError::serialization(e.to_string()))
    })?;

    if let Some(path) = output_file {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| {
                    KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                        "create file: {e}"
                    )))
                })?;
            file.write_all(json_str.as_bytes()).map_err(|e| {
                KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                    "write file: {e}"
                )))
            })?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::File::create(path).map_err(|e| {
                KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                    "create file: {}",
                    e
                )))
            })?;
            file.write_all(json_str.as_bytes()).map_err(|e| {
                KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                    "write file: {}",
                    e
                )))
            })?;
        }
        out.newline();
        out.field("Share index", &exported.share_index.to_string());
        out.field(
            "Threshold",
            &format!("{}-of-{}", exported.threshold, exported.participants),
        );
        out.success(&format!("Share exported to {path}"));
    } else {
        println!("{json_str}");
    }

    Ok(())
}
