// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use secrecy::ExposeSecret;

use keep_core::error::{KeepError, Result};
use keep_core::wallet::WalletDescriptor;
use keep_core::Keep;

use crate::cli::WalletExportFormat;
use crate::output::Output;

use super::get_password;

fn parse_group_hex(group_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(group_hex)
        .map_err(|e| KeepError::InvalidInput(format!("invalid group hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeepError::InvalidInput("group pubkey must be 32 bytes".into()))?;
    Ok(arr)
}

pub fn cmd_wallet_list(out: &Output, path: &Path) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let descriptors = keep.list_wallet_descriptors()?;

    if descriptors.is_empty() {
        out.newline();
        out.info("No wallet descriptors found. Use 'keep wallet descriptor' to create one.");
        return Ok(());
    }

    out.table_header(&[("GROUP", 18), ("NETWORK", 10), ("DESCRIPTOR", 40)]);

    for desc in &descriptors {
        let group_short = hex::encode(&desc.group_pubkey[..8]);
        let desc_display = if desc.external_descriptor.len() > 36 {
            format!("{}...", &desc.external_descriptor[..36])
        } else {
            desc.external_descriptor.clone()
        };
        out.table_row(&[
            (&format!("{group_short}..."), 18, false),
            (&desc.network, 10, false),
            (&desc_display, 40, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} descriptor(s) total", descriptors.len()));

    Ok(())
}

pub fn cmd_wallet_show(out: &Output, path: &Path, group_hex: &str) -> Result<()> {
    let group_pubkey = parse_group_hex(group_hex)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let desc = keep
        .get_wallet_descriptor(&group_pubkey)?
        .ok_or_else(|| KeepError::KeyNotFound("no descriptor for this group".into()))?;

    out.newline();
    out.header("Wallet Descriptor");
    out.field("Group", &hex::encode(desc.group_pubkey));
    out.field("Network", &desc.network);
    out.field("Created", &desc.created_at.to_string());
    out.newline();
    out.info("External descriptor (receive):");
    println!("{}", desc.external_descriptor);
    out.newline();
    out.info("Internal descriptor (change):");
    println!("{}", desc.internal_descriptor);

    Ok(())
}

pub fn cmd_wallet_export(
    out: &Output,
    path: &Path,
    group_hex: &str,
    format: &WalletExportFormat,
) -> Result<()> {
    let group_pubkey = parse_group_hex(group_hex)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let desc = keep
        .get_wallet_descriptor(&group_pubkey)?
        .ok_or_else(|| KeepError::KeyNotFound("no descriptor for this group".into()))?;

    match format {
        WalletExportFormat::Plain => {
            out.newline();
            out.header("Wallet Descriptor Export");
            out.newline();
            out.info("External descriptor (receive):");
            println!("{}", desc.external_descriptor);
            out.newline();
            out.info("Internal descriptor (change):");
            println!("{}", desc.internal_descriptor);
        }
        WalletExportFormat::Sparrow => {
            let network = crate::commands::bitcoin::parse_network(&desc.network)?;
            let export = keep_bitcoin::DescriptorExport::from_frost_wallet(
                &desc.group_pubkey,
                None,
                network,
            )
            .map_err(|e| KeepError::Runtime(e.to_string()))?;

            let group_short = hex::encode(&desc.group_pubkey[..8]);
            let json = export
                .to_sparrow_json(&format!("frost-{group_short}"))
                .map_err(|e| KeepError::Runtime(e.to_string()))?;

            out.newline();
            out.header("Sparrow Wallet Export");
            out.newline();
            println!("{json}");
        }
    }

    Ok(())
}

pub fn cmd_wallet_descriptor(
    out: &Output,
    path: &Path,
    group_hex: &str,
    network: &str,
) -> Result<()> {
    let group_pubkey = parse_group_hex(group_hex)?;
    let net = crate::commands::bitcoin::parse_network(network)?;

    let export = keep_bitcoin::DescriptorExport::from_frost_wallet(&group_pubkey, None, net)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    let internal = export
        .internal_descriptor()
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let descriptor = WalletDescriptor {
        group_pubkey,
        external_descriptor: export.descriptor.clone(),
        internal_descriptor: internal.clone(),
        network: network.to_string(),
        created_at: now,
    };

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    keep.store_wallet_descriptor(&descriptor)?;

    out.newline();
    out.success("Wallet descriptor created and stored!");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Network", network);
    out.field("Fingerprint", &export.fingerprint);
    out.newline();
    out.info("External descriptor (receive):");
    println!("{}", export.descriptor);
    out.newline();
    out.info("Internal descriptor (change):");
    println!("{internal}");

    Ok(())
}

pub fn cmd_wallet_delete(out: &Output, path: &Path, group_hex: &str) -> Result<()> {
    let group_pubkey = parse_group_hex(group_hex)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    keep.delete_wallet_descriptor(&group_pubkey)?;

    out.newline();
    out.success(&format!(
        "Deleted wallet descriptor for group {}",
        group_hex
    ));

    Ok(())
}
