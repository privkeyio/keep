// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use nostr_sdk::prelude::*;
use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{FrostError, KeepError, NetworkError, Result};
use keep_core::wallet::WalletDescriptor;
use keep_core::Keep;

use crate::output::Output;
use crate::signer::HardwareSigner;

use super::get_password;

mod dkg;
mod hardware;

pub use dkg::{cmd_frost_network_dkg, cmd_frost_network_group_create};
pub use hardware::{cmd_frost_network_nonce_precommit, cmd_frost_network_sign_hardware};

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_serve(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
    auto_contribute_descriptor: bool,
) -> Result<()> {
    debug!(group = group_npub, relay, share = ?share_index, "starting FROST network node");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };
    let threshold = share.metadata.threshold;
    let share_index = share.metadata.identifier;
    let total_shares = share.metadata.total_shares;

    out.newline();
    out.header("FROST Network Node");
    out.field("Group", group_npub);
    out.field("Share", &share_index.to_string());
    out.field("Threshold", &format!("{threshold}-of-{total_shares}"));
    out.field("Relay", relay);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        out.info("Starting FROST coordination node...");

        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        let pk = node.pubkey();
        let npub = pk.to_bech32().unwrap_or_else(|_| format!("{pk}"));
        out.field("Node pubkey", &npub);
        out.newline();
        out.info("Listening for FROST messages... (Ctrl+C to stop)");

        let keep = std::sync::Arc::new(std::sync::Mutex::new(keep));

        let mut event_rx = node.subscribe();
        let event_node = node.clone();
        let event_keep = keep.clone();
        let event_task = tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { share_index, name }) => {
                        let name_str = name.unwrap_or_else(|| "unnamed".to_string());
                        tracing::info!(share_index, name = name_str, "peer discovered");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SignatureComplete {
                        session_id,
                        signature,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        let sig = hex::encode(signature);
                        tracing::info!(session, signature = sig, "signature complete");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SigningFailed { session_id, error }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, error, "signing failed");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorContributionNeeded {
                        session_id,
                        network,
                        initiator_pubkey,
                        ..
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        if !auto_contribute_descriptor {
                            tracing::warn!(
                                session,
                                "descriptor contribution requested but --auto-contribute-descriptor not set, ignoring"
                            );
                            continue;
                        }
                        tracing::info!(session, "descriptor contribution requested, auto-contributing");
                        let contribute_node = event_node.clone();
                        let net = network.clone();
                        tokio::spawn(async move {
                            let session = hex::encode(&session_id[..8]);
                            let derived = tokio::task::spawn_blocking({
                                let node = contribute_node.clone();
                                move || node.derive_account_xpub(&net)
                            })
                            .await;
                            let xpub_result = match derived {
                                Ok(inner) => inner,
                                Err(e) => Err(keep_frost_net::FrostNetError::Crypto(e.to_string())),
                            };
                            match xpub_result {
                                Ok((xpub, fingerprint)) => {
                                    if let Err(e) = contribute_node
                                        .contribute_descriptor(
                                            session_id,
                                            &initiator_pubkey,
                                            &xpub,
                                            &fingerprint,
                                        )
                                        .await
                                    {
                                        tracing::error!(session, error = %e, "failed to contribute descriptor");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(session, error = %e, "failed to derive xpub for contribution");
                                }
                            }
                        });
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorComplete {
                        session_id,
                        external_descriptor,
                        internal_descriptor,
                        network,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        let desc_short = match external_descriptor.get(..40) {
                            Some(prefix) => format!("{prefix}..."),
                            None => external_descriptor.clone(),
                        };
                        tracing::info!(session, descriptor = desc_short, "descriptor complete");

                        let keep = event_keep.clone();
                        tokio::task::spawn_blocking(move || {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let descriptor = WalletDescriptor {
                                group_pubkey,
                                external_descriptor,
                                internal_descriptor,
                                network,
                                created_at: now,
                            };
                            let guard = keep.lock().expect("keep mutex poisoned");
                            match guard.store_wallet_descriptor(&descriptor) {
                                Ok(()) => {
                                    tracing::info!("wallet descriptor stored");
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to store wallet descriptor");
                                }
                            }
                        });
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorNacked {
                        session_id,
                        share_index,
                        reason,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, share_index, reason, "descriptor nacked by peer");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed {
                        session_id,
                        error,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, error, "descriptor session failed");
                    }
                    Err(_) => break,
                    _ => {}
                }
            }
        });

        node.run()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        event_task.abort();

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_peers(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
) -> Result<()> {
    debug!(group = group_npub, relay, "checking FROST peers");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = keep.frost_get_share(&group_pubkey)?;

    out.newline();
    out.header("FROST Network Peers");
    out.field("Group", group_npub);
    out.field("Relay", relay);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let spinner = out.spinner("Connecting and discovering peers...");

        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        spinner.finish();
        node_handle.abort();

        let status = node.peer_status();

        if status.is_empty() {
            out.info("No peers discovered yet.");
            out.info("Run 'keep frost network serve' on other devices first.");
        } else {
            out.table_header(&[("SHARE", 8), ("STATUS", 10), ("NAME", 20)]);

            for (share_index, peer_status, name) in status {
                use keep_frost_net::PeerStatus;
                let status_str = match peer_status {
                    PeerStatus::Online => "Online",
                    PeerStatus::Offline => "Offline",
                    PeerStatus::Unknown => "Unknown",
                };
                out.table_row(&[
                    (&share_index.to_string(), 8, false),
                    (status_str, 10, false),
                    (&name.unwrap_or_else(|| "-".to_string()), 20, false),
                ]);
            }
        }

        out.newline();
        out.info(&format!("{} peer(s) online", node.online_peers()));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out, warden_url, message), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign(
    out: &Output,
    path: &Path,
    group_npub: &str,
    message: &str,
    relay: &str,
    share_index: Option<u16>,
    hardware: Option<&str>,
    warden_url: Option<&str>,
    threshold: Option<u16>,
    participants: Option<u16>,
) -> Result<()> {
    if let Some(device) = hardware {
        let (threshold, participants) = match (threshold, participants) {
            (Some(t), Some(p)) => (t, p),
            _ => {
                let mut signer = HardwareSigner::new(device).map_err(|e| {
                    KeepError::NetworkErr(NetworkError::connection(format!("hardware: {e}")))
                })?;
                let info = signer.get_share_info(group_npub).map_err(|e| {
                    KeepError::FrostErr(FrostError::session(format!(
                        "failed to get share info: {e}"
                    )))
                })?;
                (
                    threshold.unwrap_or(info.threshold),
                    participants.unwrap_or(info.participants),
                )
            }
        };
        if threshold < 2 || threshold > participants {
            return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
                "must be 2 <= threshold ({threshold}) <= participants ({participants})"
            ))));
        }
        return cmd_frost_network_sign_hardware(
            out,
            path,
            group_npub,
            message,
            relay,
            device,
            threshold,
            participants,
        );
    }

    #[cfg(feature = "warden")]
    if let Some(url) = warden_url {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;
        rt.block_on(super::frost::check_warden_policy(
            out, url, group_npub, message,
        ))?;
    }

    #[cfg(not(feature = "warden"))]
    if warden_url.is_some() {
        return Err(KeepError::NotImplemented(
            "Warden support not compiled. Rebuild with --features warden".into(),
        ));
    }

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };

    out.newline();
    out.header("FROST Network Sign");
    out.field("Group", group_npub);
    out.field(
        "Share",
        &format!("{} ({})", share.metadata.identifier, share.metadata.name),
    );
    out.field(
        "Threshold",
        &format!(
            "{}-of-{}",
            share.metadata.threshold, share.metadata.total_shares
        ),
    );
    out.field("Relay", relay);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        out.info("Starting FROST coordination node...");
        out.field(
            "Node pubkey",
            &{
                let pk = node.pubkey();
                pk.to_bech32().unwrap_or_else(|_| format!("{pk}"))
            },
        );
        out.newline();

        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _handle = tokio::spawn(async move {
            let _ = node_clone.run().await;
        });

        out.info("Discovering peers...");
        for i in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if node.online_peers() > 0 {
                break;
            }
            if i < 11 {
                out.info(&format!("  Waiting for peers... ({}/12)", i + 1));
            }
        }

        if node.online_peers() == 0 {
            return Err(KeepError::Frost("No peers online after 24s.".into()));
        }

        out.success(&format!("Found {} online peer(s)", node.online_peers()));
        out.newline();

        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let spinner = out.spinner("Requesting signature from network...");
        let signature = node
            .request_signature(message.as_bytes().to_vec(), "raw")
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.newline();
        out.success("Signature complete!");
        out.field("Signature", &hex::encode(signature));
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign_event(
    out: &Output,
    _path: &Path,
    _group_npub: &str,
    _kind: u16,
    _content: &str,
    _relay: &str,
    _share_index: Option<u16>,
    _hardware: Option<&str>,
) -> Result<()> {
    out.newline();
    out.error("FROST network event signing not yet implemented");
    out.info("Use 'keep frost network sign' to sign raw messages instead.");
    Err(KeepError::NotImplemented(
        "FROST network event signing".into(),
    ))
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_health_check(
    out: &Output,
    path: &Path,
    group: &str,
    relay: &str,
    share_index: Option<u16>,
    timeout: u64,
) -> Result<()> {
    const MAX_HEALTH_CHECK_TIMEOUT_SECS: u64 = 3600;
    if timeout == 0 || timeout > MAX_HEALTH_CHECK_TIMEOUT_SECS {
        return Err(KeepError::InvalidInput(format!(
            "timeout must be between 1 and {MAX_HEALTH_CHECK_TIMEOUT_SECS} seconds"
        )));
    }
    debug!(group, relay, share = ?share_index, timeout, "health check");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };

    out.newline();
    out.header("Key Health Check");
    out.field("Group", group);
    out.field("Relay", relay);
    out.field("Timeout", &format!("{timeout}s"));
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

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        });

        let spinner = out.spinner("Discovering peers...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        spinner.finish();

        let online = node.online_peers();
        out.info(&format!("{online} peer(s) discovered"));

        if online == 0 {
            node_handle.abort();
            out.newline();
            out.warn("No peers discovered. Run 'keep frost network serve' on other devices first.");
            return Ok::<_, KeepError>(());
        }

        let spinner = out.spinner(&format!("Pinging peers (timeout: {timeout}s)..."));
        let result = node
            .health_check(std::time::Duration::from_secs(timeout))
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();
        node_handle.abort();

        out.newline();
        out.header("Results");

        if !result.responsive.is_empty() {
            let shares: Vec<String> = result.responsive.iter().map(|s| s.to_string()).collect();
            out.field("Responsive", &shares.join(", "));
        }
        if !result.unresponsive.is_empty() {
            let shares: Vec<String> = result.unresponsive.iter().map(|s| s.to_string()).collect();
            out.field("Unresponsive", &shares.join(", "));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (&idx, responsive) in result
            .responsive
            .iter()
            .map(|i| (i, true))
            .chain(result.unresponsive.iter().map(|i| (i, false)))
        {
            let existing = keep.get_health_status(&group_pubkey, idx)?;
            let created_at = existing.and_then(|s| s.created_at).unwrap_or(now);
            let status = keep_core::wallet::KeyHealthStatus {
                group_pubkey,
                share_index: idx,
                last_check_timestamp: now,
                responsive,
                created_at: Some(created_at),
            };
            keep.store_health_status(&status)?;
        }

        out.newline();
        out.success(&format!(
            "{} responsive, {} unresponsive",
            result.responsive.len(),
            result.unresponsive.len()
        ));

        let all_statuses = keep.list_health_statuses()?;
        let group_statuses: Vec<_> = all_statuses
            .iter()
            .filter(|s| s.group_pubkey == group_pubkey)
            .collect();
        if !group_statuses.is_empty() {
            out.newline();
            out.header("Health History");
            for s in &group_statuses {
                let age = now.saturating_sub(s.last_check_timestamp);
                let status_str = if s.responsive { "responsive" } else { "unresponsive" };
                let staleness = if s.is_critical(now) {
                    " [CRITICAL]"
                } else if s.is_stale(now) {
                    " [STALE]"
                } else {
                    ""
                };
                let age_display = format_duration_ago(age);
                out.field(
                    &format!("Share {}", s.share_index),
                    &format!("{status_str} ({age_display}){staleness}"),
                );
            }
        }

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn format_duration_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}
