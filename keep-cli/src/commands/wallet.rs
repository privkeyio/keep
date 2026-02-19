// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;
use std::time::Duration;

use secrecy::ExposeSecret;
use tracing::debug;

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
        let ext = &desc.external_descriptor;
        let desc_display = if ext.len() > 36 {
            format!("{}...", &ext[..36])
        } else {
            ext.clone()
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
    out.field("External (receive)", &desc.external_descriptor);
    out.newline();
    out.field("Internal (change)", &desc.internal_descriptor);

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
            out.field("External (receive)", &desc.external_descriptor);
            out.newline();
            out.field("Internal (change)", &desc.internal_descriptor);
        }
        WalletExportFormat::Sparrow => {
            let is_mainnet = desc.network == "bitcoin" || desc.network == "mainnet";
            let network_str = if is_mainnet { "mainnet" } else { &desc.network };
            let group_short = hex::encode(&desc.group_pubkey[..8]);
            let coin_type = if is_mainnet { 0 } else { 1 };

            // keystore.type = "bip39" is required for Sparrow watch-only import
            // compatibility; Sparrow rejects unknown keystore types
            let json = serde_json::json!({
                "name": format!("frost-{group_short}"),
                "network": network_str,
                "keystore": {
                    "type": "bip39",
                    "derivation": format!("m/86'/{coin_type}'/0'"),
                },
                "outputDescriptor": desc.external_descriptor,
                "changeDescriptor": desc.internal_descriptor,
            });

            let json_str = serde_json::to_string_pretty(&json)
                .map_err(|e| KeepError::Runtime(e.to_string()))?;

            out.newline();
            out.header("Sparrow Wallet Export");
            out.newline();
            out.info(&json_str);
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

    let canonical_network = net.to_string();

    let descriptor = WalletDescriptor {
        group_pubkey,
        external_descriptor: export.descriptor.clone(),
        internal_descriptor: internal.clone(),
        network: canonical_network.clone(),
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
    out.field("Network", &canonical_network);
    out.field("Fingerprint", &export.fingerprint);
    out.newline();
    out.field("External (receive)", &export.descriptor);
    out.newline();
    out.field("Internal (change)", &internal);

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
    out.success(&format!("Deleted wallet descriptor for group {group_hex}"));

    Ok(())
}

fn parse_recovery_policy(
    recovery: &str,
    total_shares: u16,
) -> Result<keep_frost_net::WalletPolicy> {
    let parts: Vec<&str> = recovery.split('@').collect();
    if parts.len() != 2 {
        return Err(KeepError::InvalidInput(
            "Recovery format: 'ThresholdOfKeys@TimelockMonths' e.g. '2of3@6mo'".into(),
        ));
    }

    let thresh_part = parts[0];
    let timelock_part = parts[1];

    let of_parts: Vec<&str> = thresh_part.split("of").collect();
    if of_parts.len() != 2 {
        return Err(KeepError::InvalidInput(
            "Threshold format: 'NofM' e.g. '2of3'".into(),
        ));
    }

    let threshold: u32 = of_parts[0]
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid threshold number".into()))?;
    let key_count: u32 = of_parts[1]
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid key count".into()))?;

    if key_count as u16 > total_shares {
        return Err(KeepError::InvalidInput(format!(
            "Key count {key_count} exceeds total shares {total_shares}"
        )));
    }

    let timelock_months: u32 = timelock_part
        .trim_end_matches("mo")
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid timelock, use e.g. '6mo'".into()))?;

    let key_slots: Vec<keep_frost_net::KeySlot> = (1..=key_count as u16)
        .map(|i| keep_frost_net::KeySlot::Participant { share_index: i })
        .collect();

    Ok(keep_frost_net::WalletPolicy {
        recovery_tiers: vec![keep_frost_net::PolicyTier {
            threshold,
            key_slots,
            timelock_months,
        }],
    })
}

fn parse_group_id(group: &str) -> Result<[u8; 32]> {
    if group.starts_with("npub") {
        keep_core::keys::npub_to_bytes(group)
    } else {
        parse_group_hex(group)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_wallet_propose(
    out: &Output,
    path: &Path,
    group: &str,
    network: &str,
    relay: &str,
    share_index: Option<u16>,
    recovery: Option<&str>,
) -> Result<()> {
    debug!(group, network, relay, share = ?share_index, "wallet propose");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = parse_group_id(group)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };
    let total_shares = share.metadata.total_shares;

    let policy = match recovery {
        Some(r) => parse_recovery_policy(r, total_shares)?,
        None => keep_frost_net::WalletPolicy {
            recovery_tiers: vec![],
        },
    };

    out.newline();
    out.header("Wallet Descriptor Proposal");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Network", network);
    out.field("Relay", relay);
    if let Some(r) = recovery {
        out.field("Recovery", r);
    }
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        let (xpub, fingerprint) = node
            .derive_account_xpub(network)
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        out.field("Our xpub", &xpub);
        out.field("Our fingerprint", &fingerprint);
        out.newline();

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let spinner = out.spinner("Discovering peers...");

        let mut event_rx = node.subscribe();

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        });

        tokio::time::sleep(Duration::from_secs(3)).await;
        spinner.finish();

        let online = node.online_peers();
        out.info(&format!("{online} peer(s) online"));
        if online == 0 {
            node_handle.abort();
            return Err(KeepError::Frost(
                "No peers online. Run 'keep frost network serve' on other devices first.".into(),
            ));
        }
        out.newline();

        let spinner = out.spinner("Sending descriptor proposal...");
        let session_id = node
            .request_descriptor(policy, network, &xpub, &fingerprint)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.field("Session", &hex::encode(&session_id[..8]));
        out.newline();

        let spinner = out.spinner("Waiting for contributions...");
        let timeout = Duration::from_secs(keep_frost_net::DESCRIPTOR_SESSION_TIMEOUT_SECS);
        let deadline = tokio::time::Instant::now() + timeout;

        let mut ready = false;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, event_rx.recv()).await {
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorContributed {
                    share_index, ..
                })) => {
                    out.info(&format!("  Share {share_index} contributed"));
                }
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorReady { session_id: sid }))
                    if sid == session_id =>
                {
                    ready = true;
                    break;
                }
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed { error, .. })) => {
                    spinner.finish();
                    node_handle.abort();
                    return Err(KeepError::Frost(format!("Descriptor session failed: {error}")));
                }
                Ok(Err(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        spinner.finish();

        if !ready {
            node_handle.abort();
            return Err(KeepError::Frost(
                "Timed out waiting for all contributions".into(),
            ));
        }

        out.success("All contributions received!");
        out.newline();

        let spinner = out.spinner("Finalizing descriptor...");
        node.build_and_finalize_descriptor(session_id)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        let spinner = out.spinner("Waiting for ACKs...");
        let ack_deadline = tokio::time::Instant::now() + Duration::from_secs(60);

        let mut external_descriptor = String::new();
        let mut internal_descriptor = String::new();
        let mut complete = false;

        while tokio::time::Instant::now() < ack_deadline {
            let remaining = ack_deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, event_rx.recv()).await {
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorComplete {
                    session_id: sid,
                    external_descriptor: ext,
                    internal_descriptor: int,
                })) if sid == session_id => {
                    external_descriptor = ext;
                    internal_descriptor = int;
                    complete = true;
                    break;
                }
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed { error, .. })) => {
                    spinner.finish();
                    node_handle.abort();
                    return Err(KeepError::Frost(format!("Descriptor finalization failed: {error}")));
                }
                Ok(Err(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        spinner.finish();
        node_handle.abort();

        if !complete {
            return Err(KeepError::Frost(
                "Timed out waiting for descriptor ACKs".into(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let descriptor = WalletDescriptor {
            group_pubkey,
            external_descriptor: external_descriptor.clone(),
            internal_descriptor: internal_descriptor.clone(),
            network: network.to_string(),
            created_at: now,
        };

        keep.store_wallet_descriptor(&descriptor)?;

        out.newline();
        out.success("Wallet descriptor coordinated and stored!");
        out.newline();
        out.field("External (receive)", &external_descriptor);
        out.newline();
        out.field("Internal (change)", &internal_descriptor);

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}
