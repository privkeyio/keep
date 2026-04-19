// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{KeepError, Result};
use keep_core::wallet::WalletDescriptor;
use keep_core::Keep;

use crate::cli::WalletExportFormat;
use crate::output::Output;

use super::get_password;

/// Build a `KeepDescriptorLookup` from an `Arc<Mutex<Keep>>`. Logs a warning
/// and returns no match when the vault is locked or the mutex is poisoned.
fn descriptor_lookup_for(
    keep: Arc<Mutex<Keep>>,
) -> keep_frost_net::KeepDescriptorLookup<
    impl Fn() -> Option<Vec<WalletDescriptor>> + Send + Sync + 'static,
> {
    keep_frost_net::KeepDescriptorLookup::new(move || {
        let guard = keep.lock().ok()?;
        guard.list_wallet_descriptors().ok()
    })
}

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
        device_registrations: Vec::new(),
        policy_hash: [0u8; 32],
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

pub fn cmd_wallet_register(
    out: &Output,
    path: &Path,
    group: &str,
    device_uri: &str,
    name: Option<&str>,
    show_token: bool,
) -> Result<()> {
    debug!(group, device = %mask_secret(device_uri), "wallet register");

    let group_pubkey = parse_group_id(group)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let desc = keep
        .get_wallet_descriptor(&group_pubkey)?
        .ok_or_else(|| KeepError::KeyNotFound("no descriptor for this group".into()))?;

    let wallet_name = name
        .map(str::to_string)
        .unwrap_or_else(|| format!("keep-{}", hex::encode(&group_pubkey[..4])));
    if wallet_name.is_empty() {
        return Err(KeepError::InvalidInput(
            "wallet name must not be empty".into(),
        ));
    }
    if wallet_name.len() > keep_nip46::MAX_WALLET_NAME_LEN {
        return Err(KeepError::InvalidInput(format!(
            "wallet name exceeds {} bytes",
            keep_nip46::MAX_WALLET_NAME_LEN
        )));
    }

    let multipath = keep_bitcoin::multipath_from_external(&desc.external_descriptor)
        .map_err(|e| KeepError::Runtime(format!("build multipath descriptor: {e}")))?;
    if multipath.len() > keep_nip46::MAX_DESCRIPTOR_LEN {
        return Err(KeepError::InvalidInput(format!(
            "descriptor exceeds {} bytes",
            keep_nip46::MAX_DESCRIPTOR_LEN
        )));
    }

    out.newline();
    out.header("Register Wallet on Hardware Signer");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Network", &desc.network);
    out.field("Wallet name", &wallet_name);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let register_outcome = rt.block_on(async {
        let spinner = out.spinner("Connecting to signer...");
        let client = keep_nip46::Nip46Client::connect_to(device_uri)
            .await
            .map_err(|e| KeepError::Runtime(format!("connect: {e}")))?;
        spinner.finish();
        let signer = client.signer_pubkey();

        let outcome = async {
            let spinner = out.spinner("Authenticating with signer...");
            client
                .connect()
                .await
                .map_err(|e| KeepError::Runtime(format!("handshake: {e}")))?;
            spinner.finish();

            let spinner = out.spinner("Registering wallet on device (confirm on device)...");
            let response = client
                .register_wallet(&wallet_name, &multipath)
                .await
                .map_err(|e| KeepError::Runtime(format!("register_wallet: {e}")))?;
            spinner.finish();
            Ok::<_, KeepError>(response)
        }
        .await;

        client.disconnect().await;
        Ok::<_, KeepError>((signer, outcome?))
    });
    // Give nostr_sdk background tasks a chance to flush before we tear the
    // runtime down; avoids aborting in-flight disconnect cleanup.
    rt.shutdown_timeout(Duration::from_secs(2));

    let (signer_pubkey, response) = register_outcome?;

    let signer_bytes = signer_pubkey.to_bytes();
    let signer_hex = hex::encode(signer_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Surface the device-side outcome before attempting local persistence so an
    // operator knows registration already took effect on the signer if the
    // local save errors below. Re-running register is idempotent.
    out.success("Device accepted the wallet registration");
    out.field("Signer pubkey", &signer_hex);
    match response.hmac.as_deref() {
        Some(hmac) => out.field("Registration token", &format_token(hmac, show_token)),
        None => out.info("Device did not return a registration token."),
    }

    let token_status = if response.hmac.is_some() {
        "received"
    } else {
        "none"
    };
    keep.upsert_device_registration(
        &group_pubkey,
        keep_core::DeviceRegistration {
            signer_pubkey: signer_bytes,
            wallet_name: wallet_name.clone(),
            hmac: response.hmac.clone(),
            registered_at: now,
        },
    )
    .map_err(|e| {
        KeepError::Other(format!(
            "device registration already succeeded on signer {signer_hex} (token: {token_status}) but saving to local descriptor failed: {e}; re-running register is safe"
        ))
    })?;

    out.info("Registration saved to wallet descriptor.");

    Ok(())
}

pub fn cmd_wallet_registrations(
    out: &Output,
    path: &Path,
    group: &str,
    show_token: bool,
) -> Result<()> {
    let group_pubkey = parse_group_id(group)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let desc = keep
        .get_wallet_descriptor(&group_pubkey)?
        .ok_or_else(|| KeepError::KeyNotFound("no descriptor for this group".into()))?;

    out.newline();
    out.header("Registered Hardware Signers");
    out.field("Group", &hex::encode(group_pubkey));

    if desc.device_registrations.is_empty() {
        out.info("No hardware signers have registered this wallet.");
        return Ok(());
    }

    for reg in &desc.device_registrations {
        out.newline();
        out.field("Signer pubkey", &hex::encode(reg.signer_pubkey));
        out.field("Wallet name", &reg.wallet_name);
        out.field("Registered at", &format_registered_at(reg.registered_at));
        if let Some(hmac) = reg.hmac.as_deref() {
            out.field("Registration token", &format_token(hmac, show_token));
        }
    }

    Ok(())
}

fn mask_secret(uri: &str) -> String {
    match url::Url::parse(uri) {
        Ok(mut parsed) => {
            let pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| match k.as_ref() {
                    "secret" => (k.into_owned(), "***".into()),
                    // relay hostnames may include .onion or internal hosts we
                    // don't want echoed to logs; truncate to a short prefix.
                    "relay" => (k.into_owned(), truncate_relay_for_log(&v)),
                    _ => (k.into_owned(), v.into_owned()),
                })
                .collect();
            parsed.query_pairs_mut().clear();
            for (k, v) in pairs {
                parsed.query_pairs_mut().append_pair(&k, &v);
            }
            parsed.to_string()
        }
        Err(_) => "<invalid>".into(),
    }
}

fn truncate_relay_for_log(relay: &str) -> String {
    const PREFIX_LEN: usize = 16;
    if relay.len() <= PREFIX_LEN {
        return relay.to_string();
    }
    let prefix: String = relay.chars().take(PREFIX_LEN).collect();
    format!("{prefix}...")
}

fn format_token(hmac: &[u8], show_token: bool) -> String {
    if show_token {
        hex::encode(hmac)
    } else {
        format!(
            "[redacted; {} bytes] (use --show-token to reveal)",
            hmac.len()
        )
    }
}

fn format_registered_at(ts: u64) -> String {
    let signed = i64::try_from(ts).unwrap_or(i64::MAX);
    chrono::DateTime::<chrono::Utc>::from_timestamp(signed, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
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
    timeout_secs: Option<u64>,
) -> Result<()> {
    debug!(group, network, relay, share = ?share_index, timeout = ?timeout_secs, "wallet propose");

    if let Some(t) = timeout_secs {
        if t == 0 || t > keep_frost_net::DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS {
            return Err(KeepError::InvalidInput(format!(
                "timeout must be between 1 and {} seconds",
                keep_frost_net::DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS
            )));
        }
    }

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

    let keep = Arc::new(Mutex::new(keep));

    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        let node = node.with_descriptor_lookup(Arc::new(descriptor_lookup_for(keep.clone())));
        let node = std::sync::Arc::new(node);

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
            .request_descriptor_with_timeout(policy, network, &xpub, &fingerprint, timeout_secs)
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
            let effective_timeout = timeout_secs.unwrap_or(keep_frost_net::DESCRIPTOR_SESSION_TIMEOUT_SECS);
            let timeout = Duration::from_secs(effective_timeout);
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
        let default_ack = keep_frost_net::DESCRIPTOR_ACK_TIMEOUT_SECS;
        let ack_timeout = timeout_secs
            .map(|t| t.clamp(default_ack, default_ack * 4))
            .unwrap_or(default_ack);
        let ack_deadline = tokio::time::Instant::now() + Duration::from_secs(ack_timeout);

        let mut external_descriptor = String::new();
        let mut internal_descriptor = String::new();
        let mut finalized_policy_hash = [0u8; 32];
        let mut complete = false;

        while tokio::time::Instant::now() < ack_deadline {
            let remaining = ack_deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, event_rx.recv()).await {
                Ok(Ok(keep_frost_net::KfpNodeEvent::DescriptorComplete {
                    session_id: sid,
                    external_descriptor: ext,
                    internal_descriptor: int,
                    policy_hash,
                    ..
                })) if sid == session_id => {
                    external_descriptor = ext;
                    internal_descriptor = int;
                    finalized_policy_hash = policy_hash;
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
            device_registrations: Vec::new(),
            policy_hash: finalized_policy_hash,
        };

        keep.lock()
            .map_err(|_| KeepError::Runtime("Keep mutex poisoned".into()))?
            .store_wallet_descriptor(&descriptor)?;

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

    let keep = Arc::new(Mutex::new(keep));

    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        let node = node.with_descriptor_lookup(Arc::new(descriptor_lookup_for(keep.clone())));
        let node = std::sync::Arc::new(node);

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

#[allow(clippy::too_many_arguments)]
pub fn cmd_wallet_spend(
    out: &Output,
    path: &Path,
    group: &str,
    recovery_tier: u32,
    psbt_file: &Path,
    fee: u64,
    threshold: u32,
    signer_share: &[u16],
    signer_fingerprint: &[String],
    share_index: Option<u16>,
    relay: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    debug!(group, recovery_tier, relay, timeout = ?timeout_secs, "wallet spend");

    if let Some(t) = timeout_secs {
        if t == 0 || t > keep_frost_net::PSBT_SESSION_MAX_TIMEOUT_SECS {
            return Err(KeepError::InvalidInput(format!(
                "timeout must be between 1 and {} seconds",
                keep_frost_net::PSBT_SESSION_MAX_TIMEOUT_SECS
            )));
        }
    }

    if signer_share.is_empty() && signer_fingerprint.is_empty() {
        return Err(KeepError::InvalidInput(
            "must specify at least one --signer-share or --signer-fingerprint".into(),
        ));
    }
    if threshold == 0 {
        return Err(KeepError::InvalidInput(
            "--threshold must be non-zero".into(),
        ));
    }

    let mut seen_shares = std::collections::HashSet::new();
    let mut signer_share_dedup: Vec<u16> = Vec::with_capacity(signer_share.len());
    for idx in signer_share {
        if !seen_shares.insert(*idx) {
            return Err(KeepError::InvalidInput(format!(
                "duplicate --signer-share: {idx}"
            )));
        }
        signer_share_dedup.push(*idx);
    }

    let mut seen_fps = std::collections::HashSet::new();
    let mut signer_fingerprint_dedup: Vec<String> = Vec::with_capacity(signer_fingerprint.len());
    for fp in signer_fingerprint {
        if fp.len() != 8 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(KeepError::InvalidInput(format!(
                "--signer-fingerprint '{fp}' must be 8 hex characters"
            )));
        }
        let lower = fp.to_ascii_lowercase();
        if !seen_fps.insert(lower.clone()) {
            return Err(KeepError::InvalidInput(format!(
                "duplicate --signer-fingerprint: {lower}"
            )));
        }
        signer_fingerprint_dedup.push(lower);
    }
    let signer_fingerprint = signer_fingerprint_dedup;

    let signer_share: &[u16] = &signer_share_dedup;
    let total_signers = signer_share.len() + signer_fingerprint.len();
    if (threshold as usize) > total_signers {
        return Err(KeepError::InvalidInput(format!(
            "--threshold {threshold} exceeds total signers {total_signers}"
        )));
    }

    let group_pubkey = parse_group_id(group)?;

    let psbt_bytes = read_psbt_file(psbt_file)?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let descriptor = keep
        .get_wallet_descriptor(&group_pubkey)?
        .ok_or_else(|| KeepError::KeyNotFound("no wallet descriptor for this group".into()))?;

    if descriptor.policy_hash == [0u8; 32] {
        return Err(KeepError::InvalidInput(
            "descriptor has placeholder policy_hash; coordinate via `keep wallet propose` before spending".into(),
        ));
    }

    let descriptor_hash = descriptor.canonical_hash();

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };

    out.newline();
    out.header("WDC Recovery Spend Proposal");
    out.field("Group", &hex::encode(group_pubkey));
    out.field("Network", &descriptor.network);
    out.field("Recovery tier", &recovery_tier.to_string());
    out.field("PSBT bytes", &psbt_bytes.len().to_string());
    out.field("Fee (display)", &format!("{fee} sats"));
    out.field(
        "Expected signers",
        &format!(
            "{} share(s) + {} external",
            signer_share.len(),
            signer_fingerprint.len()
        ),
    );
    out.field("Required threshold", &threshold.to_string());
    out.field("Relay", relay);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let keep = Arc::new(Mutex::new(keep));

    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        let node = node.with_descriptor_lookup(Arc::new(descriptor_lookup_for(keep.clone())));
        let node = std::sync::Arc::new(node);

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let spinner = out.spinner("Discovering peers...");
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
                "No peers online. Start 'keep frost network serve' on the recovery key holders' devices first.".into(),
            ));
        }

        let mut event_rx = node.subscribe();

        let spinner = out.spinner("Sending PSBT proposal...");
        let session_id = node
            .request_psbt_spend(
                descriptor_hash,
                recovery_tier,
                psbt_bytes,
                fee,
                threshold,
                signer_share.to_vec(),
                signer_fingerprint.clone(),
                Vec::new(),
                Vec::new(),
                timeout_secs,
            )
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.field("Session", &hex::encode(&session_id[..8]));
        out.newline();
        out.info("PSBT coordination proposed. Waiting for signatures and finalization...");

        let wait_deadline = timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(keep_frost_net::PSBT_SESSION_TIMEOUT_SECS));
        let wait_spinner = out.spinner("Waiting for PSBT coordination...");
        enum WaitOutcome {
            Finalized(Option<[u8; 32]>),
            Aborted(String),
            LocalAbort(&'static str),
        }
        let outcome: WaitOutcome = async {
            let deadline = tokio::time::Instant::now() + wait_deadline;
            loop {
                let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
                    Some(r) => r,
                    None => {
                        return WaitOutcome::LocalAbort(
                            "Timed out waiting for PSBT coordination to complete",
                        );
                    }
                };
                match tokio::time::timeout(remaining, event_rx.recv()).await {
                    Ok(Ok(keep_frost_net::KfpNodeEvent::PsbtFinalized {
                        session_id: sid,
                        txid,
                    })) if sid == session_id => {
                        return WaitOutcome::Finalized(txid);
                    }
                    Ok(Ok(keep_frost_net::KfpNodeEvent::PsbtAborted {
                        session_id: sid,
                        reason,
                    })) if sid == session_id => {
                        return WaitOutcome::Aborted(reason);
                    }
                    Ok(Ok(keep_frost_net::KfpNodeEvent::PsbtSignatureReceived {
                        session_id: sid,
                        signature_count,
                        threshold,
                        ..
                    })) if sid == session_id => {
                        tracing::info!(
                            session = %hex::encode(&sid[..8]),
                            signature_count,
                            threshold,
                            "Received PSBT signature"
                        );
                    }
                    Ok(Err(_)) => {
                        return WaitOutcome::LocalAbort(
                            "Event channel closed before PSBT finalized",
                        );
                    }
                    Err(_) => {
                        return WaitOutcome::LocalAbort(
                            "Timed out waiting for PSBT coordination to complete",
                        );
                    }
                    _ => {}
                }
            }
        }
        .await;
        wait_spinner.finish();

        let result: Result<Option<[u8; 32]>> = match outcome {
            WaitOutcome::Finalized(txid) => Ok(txid),
            WaitOutcome::Aborted(reason) => {
                Err(KeepError::Frost(format!("PSBT session aborted: {reason}")))
            }
            WaitOutcome::LocalAbort(reason) => {
                if let Err(e) = node.abort_psbt_session(session_id, reason).await {
                    tracing::warn!(
                        session = %hex::encode(&session_id[..8]),
                        error = %e,
                        "Failed to notify peers of PSBT abort"
                    );
                }
                Err(KeepError::Frost(reason.to_string()))
            }
        };

        node_handle.abort();
        match result {
            Ok(Some(txid)) => {
                out.success("PSBT finalized");
                out.field("Txid", &hex::encode(txid));
            }
            Ok(None) => {
                out.success("PSBT finalized (no final tx attached)");
            }
            Err(e) => return Err(e),
        }
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn read_psbt_file(path: &Path) -> Result<Vec<u8>> {
    // Cap file size before touching it so a hostile caller cannot exhaust
    // memory by pointing at a huge file. The `* 2` budget accounts for
    // base64-encoded PSBTs, which inflate the raw size by ~4/3.
    const MAX_PSBT_FILE_BYTES: u64 = (keep_frost_net::MAX_PSBT_SIZE as u64) * 2;
    let meta = std::fs::metadata(path)
        .map_err(|e| KeepError::InvalidInput(format!("cannot stat PSBT file: {e}")))?;
    if meta.len() > MAX_PSBT_FILE_BYTES {
        return Err(KeepError::InvalidInput(format!(
            "PSBT file is {} bytes, exceeds maximum {MAX_PSBT_FILE_BYTES}",
            meta.len()
        )));
    }
    let raw = std::fs::read(path)
        .map_err(|e| KeepError::InvalidInput(format!("cannot read PSBT file: {e}")))?;
    // Accept either raw PSBT binary (prefix "psbt\xff") or base64-encoded text.
    if raw.starts_with(b"psbt\xff") {
        return Ok(raw);
    }
    let text = String::from_utf8(raw.clone()).map_err(|_| {
        KeepError::InvalidInput("PSBT file is neither binary PSBT nor UTF-8".into())
    })?;
    use base64::{engine::general_purpose::STANDARD, Engine};
    let decoded = STANDARD
        .decode(text.trim())
        .map_err(|e| KeepError::InvalidInput(format!("cannot base64-decode PSBT: {e}")))?;
    if !decoded.starts_with(b"psbt\xff") {
        return Err(KeepError::InvalidInput(
            "decoded PSBT does not start with the PSBT magic bytes".into(),
        ));
    }
    Ok(decoded)
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

    #[test]
    fn test_mask_secret_hides_bunker_secret() {
        let uri = "bunker://aabbcc?relay=wss%3A%2F%2Frelay.example.com&secret=topsecret";
        let masked = mask_secret(uri);
        assert!(!masked.contains("topsecret"));
        assert!(masked.contains("secret=%2A%2A%2A") || masked.contains("secret=***"));
    }

    #[test]
    fn test_mask_secret_passthrough_invalid() {
        assert_eq!(mask_secret("not a url"), "<invalid>");
    }

    #[test]
    fn test_mask_secret_truncates_relay() {
        let uri = "bunker://aabbcc?relay=wss%3A%2F%2Fabcdefghijklmnop.onion%2Fpath&secret=x";
        let masked = mask_secret(uri);
        assert!(!masked.contains("abcdefghijklmnop.onion/path"));
        assert!(masked.contains("secret=%2A%2A%2A") || masked.contains("secret=***"));
    }

    #[test]
    fn test_format_registered_at_rfc3339() {
        let formatted = format_registered_at(0);
        assert_eq!(formatted, "1970-01-01T00:00:00+00:00");
    }
}
