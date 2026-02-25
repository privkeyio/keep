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
        let desc_display = match ext.get(..36) {
            Some(prefix) if ext.len() > 36 => format!("{prefix}..."),
            _ => ext.clone(),
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

const BLOCKS_PER_MONTH: u32 = 144 * 30;
const MAX_CSV_BLOCKS: u32 = 0xFFFF;

fn parse_recovery_tier(spec: &str, total_shares: u16) -> Result<keep_frost_net::PolicyTier> {
    let parts: Vec<&str> = spec.split('@').collect();
    if parts.len() != 2 {
        return Err(KeepError::InvalidInput(
            "Recovery format: 'ThresholdOfKeys@TimelockMonths' e.g. '2of3@6mo'".into(),
        ));
    }

    let thresh_part = parts[0];
    let timelock_part = parts[1];

    let (of_spec, explicit_slots) = if let Some(bracket_start) = thresh_part.find('[') {
        let of_spec = &thresh_part[..bracket_start];
        let bracket_end = thresh_part.rfind(']').ok_or_else(|| {
            KeepError::InvalidInput("Missing closing ']' in bracket notation".into())
        })?;
        if bracket_end <= bracket_start {
            return Err(KeepError::InvalidInput(
                "Missing closing ']' in bracket notation".into(),
            ));
        }
        let bracket_content = &thresh_part[bracket_start + 1..bracket_end];
        let slots: Vec<keep_frost_net::KeySlot> = bracket_content
            .split(',')
            .map(|s| {
                let s = s.trim();
                if let Some(ext_data) = s.strip_prefix("ext:") {
                    let slash_pos = ext_data.rfind('/').ok_or_else(|| {
                        KeepError::InvalidInput("External key format: ext:XPUB/FINGERPRINT".into())
                    })?;
                    let xpub = &ext_data[..slash_pos];
                    let fingerprint = &ext_data[slash_pos + 1..];
                    if xpub.is_empty() || fingerprint.is_empty() {
                        return Err(KeepError::InvalidInput(
                            "External key xpub and fingerprint must not be empty".into(),
                        ));
                    }
                    Ok(keep_frost_net::KeySlot::External {
                        xpub: xpub.to_string(),
                        fingerprint: fingerprint.to_string(),
                    })
                } else {
                    let idx: u16 = s.parse().map_err(|_| {
                        KeepError::InvalidInput(format!(
                            "Invalid bracket entry '{s}': use a number or ext:XPUB/FINGERPRINT"
                        ))
                    })?;
                    Ok(keep_frost_net::KeySlot::Participant { share_index: idx })
                }
            })
            .collect::<Result<Vec<_>>>()?;
        (of_spec, Some(slots))
    } else {
        (thresh_part, None)
    };

    let of_parts: Vec<&str> = of_spec.split("of").collect();
    if of_parts.len() != 2 {
        return Err(KeepError::InvalidInput(
            "Threshold format: 'NofM' e.g. '2of3' or '2of3[1,3,5]'".into(),
        ));
    }

    let threshold: u32 = of_parts[0]
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid threshold number".into()))?;
    let key_count: u16 = of_parts[1]
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid key count".into()))?;

    if threshold == 0 || threshold > key_count as u32 {
        return Err(KeepError::InvalidInput(format!(
            "Threshold {threshold} must be between 1 and key count {key_count}"
        )));
    }

    if let Some(ref slots) = explicit_slots {
        if slots.len() != key_count as usize {
            return Err(KeepError::InvalidInput(format!(
                "Bracket list has {} entries but key count is {key_count}",
                slots.len()
            )));
        }
        let mut seen_keys = std::collections::HashSet::new();
        for slot in slots {
            match slot {
                keep_frost_net::KeySlot::Participant { share_index } => {
                    if *share_index < 1 || *share_index > total_shares {
                        return Err(KeepError::InvalidInput(format!(
                            "Participant index {share_index} must be between 1 and {total_shares}"
                        )));
                    }
                    if !seen_keys.insert(format!("p:{share_index}")) {
                        return Err(KeepError::InvalidInput(format!(
                            "Duplicate participant index {share_index} in brackets"
                        )));
                    }
                }
                keep_frost_net::KeySlot::External { xpub, fingerprint } => {
                    if !seen_keys.insert(format!("e:{xpub}/{fingerprint}")) {
                        return Err(KeepError::InvalidInput(format!(
                            "Duplicate external key {fingerprint} in brackets"
                        )));
                    }
                }
            }
        }
    } else if key_count > total_shares {
        return Err(KeepError::InvalidInput(format!(
            "Key count {key_count} exceeds total shares {total_shares}"
        )));
    }

    let timelock_months: u32 = timelock_part
        .trim_end_matches("mo")
        .parse()
        .map_err(|_| KeepError::InvalidInput("Invalid timelock, use e.g. '6mo'".into()))?;

    if timelock_months == 0 {
        return Err(KeepError::InvalidInput(
            "Timelock must be at least 1 month".into(),
        ));
    }

    let timelock_blocks = timelock_months
        .checked_mul(BLOCKS_PER_MONTH)
        .ok_or_else(|| {
            KeepError::InvalidInput(format!(
                "Timelock {timelock_months} months overflows block count"
            ))
        })?;
    if timelock_blocks > MAX_CSV_BLOCKS {
        return Err(KeepError::InvalidInput(format!(
            "Timelock {timelock_months} months ({timelock_blocks} blocks) exceeds Bitcoin CSV maximum ({MAX_CSV_BLOCKS} blocks, ~{} months)",
            MAX_CSV_BLOCKS / BLOCKS_PER_MONTH
        )));
    }

    let key_slots: Vec<keep_frost_net::KeySlot> = explicit_slots.unwrap_or_else(|| {
        (1..=key_count)
            .map(|i| keep_frost_net::KeySlot::Participant { share_index: i })
            .collect()
    });

    Ok(keep_frost_net::PolicyTier {
        threshold,
        key_slots,
        timelock_months,
    })
}

fn parse_recovery_policy(
    specs: &[String],
    total_shares: u16,
) -> Result<keep_frost_net::WalletPolicy> {
    let mut tiers: Vec<keep_frost_net::PolicyTier> = specs
        .iter()
        .map(|spec| parse_recovery_tier(spec, total_shares))
        .collect::<Result<Vec<_>>>()?;

    tiers.sort_by_key(|t| t.timelock_months);

    for w in tiers.windows(2) {
        if w[1].timelock_months == w[0].timelock_months {
            return Err(KeepError::InvalidInput(format!(
                "Duplicate timelock: {}mo appears in multiple recovery tiers",
                w[0].timelock_months
            )));
        }
    }

    Ok(keep_frost_net::WalletPolicy {
        recovery_tiers: tiers,
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
    recovery: &[String],
) -> Result<()> {
    debug!(group, network, relay, share = ?share_index, "wallet propose");

    if !keep_frost_net::VALID_NETWORKS.contains(&network) {
        return Err(KeepError::InvalidInput(format!(
            "Invalid network '{network}' (valid: {})",
            keep_frost_net::VALID_NETWORKS.join(", ")
        )));
    }

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

    let policy = parse_recovery_policy(recovery, total_shares)?;

    out.newline();
    out.header("Wallet Descriptor Proposal");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Network", network);
    out.field("Relay", relay);
    for spec in recovery {
        out.field("Recovery", spec);
    }
    out.newline();

    let contributor_indices = keep_frost_net::participant_indices(&policy);
    let our_index = share.metadata.identifier;
    let we_contribute = contributor_indices.contains(&our_index);
    let remaining_contributions = if we_contribute {
        contributor_indices.len().saturating_sub(1)
    } else {
        contributor_indices.len()
    };

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

        macro_rules! handle_nack {
            ($spinner:expr, $sid:expr, $share_index:expr, $reason:expr) => {{
                $spinner.finish();
                node.cancel_descriptor_session(&$sid);
                node_handle.abort();
                return Err(KeepError::Frost(format!(
                    "Peer {} rejected descriptor: {}",
                    $share_index, $reason
                )));
            }};
        }

        if remaining_contributions > 0 {
            let spinner = out.spinner(&format!(
                "Waiting for contributions (0/{remaining_contributions})..."
            ));
            let timeout = Duration::from_secs(keep_frost_net::DESCRIPTOR_SESSION_TIMEOUT_SECS);
            let deadline = tokio::time::Instant::now() + timeout;

            let mut received = 0usize;
            let mut ready = false;
            while tokio::time::Instant::now() < deadline {
                let remaining = deadline - tokio::time::Instant::now();
                match tokio::time::timeout(remaining, event_rx.recv()).await {
                    Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorContributed {
                        session_id: sid,
                        share_index,
                    })) if sid == session_id => {
                        received += 1;
                        out.info(&format!(
                            "  Share {share_index} contributed ({received}/{remaining_contributions})"
                        ));
                    }
                    Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorReady { session_id: sid }))
                        if sid == session_id =>
                    {
                        ready = true;
                        break;
                    }
                    Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorNacked {
                        session_id: sid,
                        share_index,
                        reason,
                    })) if sid == session_id => {
                        handle_nack!(spinner, sid, share_index, reason);
                    }
                    Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed {
                        session_id: sid,
                        error,
                    })) if sid == session_id => {
                        spinner.finish();
                        node.cancel_descriptor_session(&session_id);
                        node_handle.abort();
                        return Err(KeepError::Frost(format!(
                            "Descriptor session failed: {error}"
                        )));
                    }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            spinner.finish();

            if !ready {
                node.cancel_descriptor_session(&session_id);
                node_handle.abort();
                return Err(KeepError::Frost(
                    "Timed out waiting for all contributions".into(),
                ));
            }
        }

        out.success("All contributions received!");
        out.newline();

        let spinner = out.spinner("Finalizing descriptor...");
        node.build_and_finalize_descriptor(session_id)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        let spinner = out.spinner("Waiting for ACKs...");
        let ack_deadline =
            tokio::time::Instant::now() + Duration::from_secs(keep_frost_net::DESCRIPTOR_ACK_TIMEOUT_SECS);

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
                    ..
                })) if sid == session_id => {
                    external_descriptor = ext;
                    internal_descriptor = int;
                    complete = true;
                    break;
                }
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorNacked {
                    session_id: sid,
                    share_index,
                    reason,
                })) if sid == session_id => {
                    handle_nack!(spinner, sid, share_index, reason);
                }
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed {
                    session_id: sid,
                    error,
                })) if sid == session_id => {
                    spinner.finish();
                    node.cancel_descriptor_session(&session_id);
                    node_handle.abort();
                    return Err(KeepError::Frost(format!(
                        "Descriptor finalization failed: {error}"
                    )));
                }
                Ok(Err(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        spinner.finish();
        node_handle.abort();

        if !complete {
            node.cancel_descriptor_session(&session_id);
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
            external_descriptor,
            internal_descriptor,
            network: network.to_string(),
            created_at: now,
        };

        keep.store_wallet_descriptor(&descriptor)?;

        out.newline();
        out.success("Wallet descriptor coordinated and stored!");
        out.newline();
        out.field("External (receive)", &descriptor.external_descriptor);
        out.newline();
        out.field("Internal (change)", &descriptor.internal_descriptor);

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn parse_announced_xpub(s: &str) -> Result<keep_frost_net::AnnouncedXpub> {
    let err_msg = "Expected format: 'xpub.../fingerprint' or 'xpub.../fingerprint/label'";
    let is_fingerprint = |s: &str| s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit());

    let last_slash = s
        .rfind('/')
        .ok_or_else(|| KeepError::InvalidInput(err_msg.into()))?;
    let (before_last, after_last) = (&s[..last_slash], &s[last_slash + 1..]);

    let (xpub, fingerprint, label) = if is_fingerprint(after_last) {
        (before_last.to_string(), after_last.to_string(), None)
    } else {
        let second_last = before_last
            .rfind('/')
            .ok_or_else(|| KeepError::InvalidInput(err_msg.into()))?;
        let fp = &before_last[second_last + 1..];
        if !is_fingerprint(fp) {
            return Err(KeepError::InvalidInput(
                "fingerprint must be exactly 8 hex characters".into(),
            ));
        }
        (
            before_last[..second_last].to_string(),
            fp.to_string(),
            Some(after_last.to_string()),
        )
    };

    if xpub.len() < keep_frost_net::MIN_XPUB_LENGTH {
        return Err(KeepError::InvalidInput(err_msg.into()));
    }
    if !keep_frost_net::VALID_XPUB_PREFIXES
        .iter()
        .any(|p| xpub.starts_with(p))
    {
        return Err(KeepError::InvalidInput(format!(
            "xpub must start with one of: {}",
            keep_frost_net::VALID_XPUB_PREFIXES.join(", ")
        )));
    }
    Ok(keep_frost_net::AnnouncedXpub {
        xpub,
        fingerprint,
        label,
    })
}

pub fn cmd_wallet_announce_keys(
    out: &Output,
    path: &Path,
    group: &str,
    relay: &str,
    share_index: Option<u16>,
    xpub_args: &[String],
) -> Result<()> {
    debug!(group, relay, share = ?share_index, "wallet announce-keys");

    let recovery_xpubs: Vec<keep_frost_net::AnnouncedXpub> = xpub_args
        .iter()
        .map(|s| parse_announced_xpub(s))
        .collect::<Result<Vec<_>>>()?;

    if recovery_xpubs.is_empty() {
        return Err(KeepError::InvalidInput(
            "At least one recovery xpub is required for announce".into(),
        ));
    }

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

    out.newline();
    out.header("Announce Recovery Keys");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Relay", relay);
    for xpub in &recovery_xpubs {
        let label = xpub.label.as_deref().unwrap_or("(none)");
        let prefix: String = xpub.xpub.chars().take(12).collect();
        out.field("Xpub", &format!("{prefix}.../{}/{label}", xpub.fingerprint));
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

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let mut event_rx = node.subscribe();

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        });

        let spinner = out.spinner("Discovering peers...");
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

        let spinner = out.spinner("Announcing recovery xpubs...");
        node.announce_xpubs(recovery_xpubs.clone())
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();
        out.success(&format!(
            "Announced {} recovery xpub(s)",
            recovery_xpubs.len()
        ));

        const ANNOUNCE_LISTEN_TIMEOUT: Duration = Duration::from_secs(15);
        let spinner = out.spinner("Listening for peer announcements...");
        let deadline = tokio::time::Instant::now() + ANNOUNCE_LISTEN_TIMEOUT;

        while tokio::time::Instant::now() < deadline {
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, event_rx.recv()).await {
                Ok(Ok(keep_frost_net::KfpNodeEvent::XpubAnnounced {
                    share_index,
                    recovery_xpubs: xpubs,
                })) => {
                    out.info(&format!(
                        "  Share {} announced {} recovery xpub(s)",
                        share_index,
                        xpubs.len()
                    ));
                }
                Ok(Err(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        spinner.finish();
        node_handle.abort();

        out.newline();
        out.success("Done! Recovery xpubs exchanged.");
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sequential_tier() {
        let tier = parse_recovery_tier("2of3@6mo", 5).unwrap();
        assert_eq!(tier.threshold, 2);
        assert_eq!(tier.key_slots.len(), 3);
        assert_eq!(tier.timelock_months, 6);
        for (i, slot) in tier.key_slots.iter().enumerate() {
            match slot {
                keep_frost_net::KeySlot::Participant { share_index } => {
                    assert_eq!(*share_index, (i + 1) as u16);
                }
                _ => panic!("expected Participant"),
            }
        }
    }

    #[test]
    fn test_parse_explicit_indices() {
        let tier = parse_recovery_tier("2of3[1,3,5]@6mo", 5).unwrap();
        assert_eq!(tier.threshold, 2);
        assert_eq!(tier.key_slots.len(), 3);
        let indices: Vec<u16> = tier
            .key_slots
            .iter()
            .map(|s| match s {
                keep_frost_net::KeySlot::Participant { share_index } => *share_index,
                _ => panic!("expected Participant"),
            })
            .collect();
        assert_eq!(indices, vec![1, 3, 5]);
    }

    #[test]
    fn test_parse_external_key() {
        let tier = parse_recovery_tier("2of3[1,2,ext:xpub6TEST/abcd1234]@6mo", 5).unwrap();
        assert_eq!(tier.threshold, 2);
        assert_eq!(tier.key_slots.len(), 3);
        match &tier.key_slots[2] {
            keep_frost_net::KeySlot::External { xpub, fingerprint } => {
                assert_eq!(xpub, "xpub6TEST");
                assert_eq!(fingerprint, "abcd1234");
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn test_parse_external_key_with_derivation_path() {
        let tier = parse_recovery_tier(
            "1of2[1,ext:[deadbeef/48h/0h/0h/2h]xpub6ABC123/deadbeef]@3mo",
            5,
        )
        .unwrap();
        match &tier.key_slots[0] {
            keep_frost_net::KeySlot::Participant { share_index } => {
                assert_eq!(*share_index, 1);
            }
            _ => panic!("expected Participant"),
        }
        match &tier.key_slots[1] {
            keep_frost_net::KeySlot::External { xpub, fingerprint } => {
                assert_eq!(xpub, "[deadbeef/48h/0h/0h/2h]xpub6ABC123");
                assert_eq!(fingerprint, "deadbeef");
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn test_parse_bracket_count_mismatch() {
        let err = parse_recovery_tier("2of3[1,2]@6mo", 5);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("2 entries but key count is 3"));
    }

    #[test]
    fn test_parse_duplicate_index() {
        let err = parse_recovery_tier("2of3[1,1,2]@6mo", 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Duplicate"));
    }

    #[test]
    fn test_parse_index_out_of_range() {
        let err = parse_recovery_tier("2of3[1,2,10]@6mo", 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("between 1 and 5"));
    }

    #[test]
    fn test_parse_invalid_external_key_format() {
        let err = parse_recovery_tier("1of1[ext:noslash]@6mo", 5);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("ext:XPUB/FINGERPRINT"));
    }

    #[test]
    fn test_parse_missing_closing_bracket() {
        let err = parse_recovery_tier("2of3[1,3,5@6mo", 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Missing closing ']'"));
    }

    #[test]
    fn test_parse_duplicate_external_key() {
        let err = parse_recovery_tier("2of2[ext:xpub6TEST/abcd1234,ext:xpub6TEST/abcd1234]@6mo", 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Duplicate external"));
    }

    #[test]
    fn test_parse_policy_duplicate_timelock() {
        let specs = vec!["2of3@6mo".to_string(), "1of2@6mo".to_string()];
        let err = parse_recovery_policy(&specs, 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Duplicate timelock"));
    }
}
