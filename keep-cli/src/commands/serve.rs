// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;
use std::sync::Arc;

use nostr_sdk::prelude::ToBech32;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;
use crate::server::Server;
use crate::signer::{FrostSigner, NetworkFrostSigner};

use super::{get_password, is_hidden_vault};

pub fn cmd_serve(
    out: &Output,
    path: &Path,
    relay: &str,
    headless: bool,
    hidden: bool,
    frost_group: Option<&str>,
    frost_relay: &str,
) -> Result<()> {
    if hidden {
        return cmd_serve_hidden(out, path, relay, headless);
    }
    if is_hidden_vault(path) {
        return cmd_serve_outer(out, path, relay, headless);
    }

    debug!(relay, headless, ?frost_group, "starting server");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    if let Some(group_npub) = frost_group {
        let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
        let share = keep.frost_get_share(&group_pubkey)?;
        let threshold = share.metadata.threshold;
        let total_shares = share.metadata.total_shares;

        out.newline();
        out.header("NIP-46 Bunker (FROST Network Mode)");
        out.field("Group", group_npub);
        out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
        out.field("FROST Relay", frost_relay);
        out.field("Bunker Relay", relay);
        out.newline();

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

        return rt.block_on(async {
            out.info("Connecting to FROST network...");
            let node = keep_frost_net::KfpNode::new(share, vec![frost_relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?;

            node.announce()
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?;

            let node = std::sync::Arc::new(node);
            let node_for_task = node.clone();
            let _node_handle = tokio::spawn(async move {
                if let Err(e) = node_for_task.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            });

            let net_signer = NetworkFrostSigner::with_shared_node(group_pubkey, node);
            out.success("Connected to FROST network");

            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();

            let mut server =
                Server::new_network_frost(net_signer, transport_key, relay, None).await?;
            let bunker_url = server.bunker_url();
            out.field("Bunker URL", &bunker_url);
            out.newline();
            out.info("Listening for NIP-46 requests...");
            out.info("(Sign requests will coordinate with FROST peers)");
            server.run().await
        });
    }

    let shares = keep.frost_list_shares()?;
    let frost_signer = if !shares.is_empty() {
        let first_group = &shares[0].metadata.group_pubkey;
        let group_shares: Vec<_> = shares
            .iter()
            .filter(|s| &s.metadata.group_pubkey == first_group)
            .cloned()
            .collect();
        let threshold = group_shares[0].metadata.threshold as usize;
        let total = group_shares.len();
        if total >= threshold {
            let data_key = keep.data_key()?;
            let group_pubkey = *first_group;
            match FrostSigner::new(group_pubkey, group_shares, data_key) {
                Ok(signer) => {
                    out.info(&format!("Using FROST signing ({}-of-{})", threshold, total));
                    Some(signer)
                }
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    if headless {
        rt.block_on(async {
            let mut server = if let Some(frost) = frost_signer {
                let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
                Server::new_frost(frost, transport_key, relay, None).await?
            } else {
                Server::new(keyring, relay, None).await?
            };
            info!(relay, bunker_url = %server.bunker_url(), "server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub, keyring_for_tui, _, transport_key_for_tui) = rt.block_on(async {
        if let Some(ref frost) = frost_signer {
            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
            let server = Server::new_frost(frost.clone(), transport_key, relay, None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
                true,
                Some(transport_key),
            ))
        } else {
            let server = Server::new(keyring.clone(), relay, None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
                false,
                None,
            ))
        }
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "runtime error", false)
                        .with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let mut server = if let (Some(frost), Some(transport_key)) =
                (frost_signer, transport_key_for_tui)
            {
                match Server::new_frost(
                    frost,
                    transport_key,
                    &relay_clone,
                    Some(tui_tx_clone.clone()),
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                }
            } else {
                match Server::new(keyring_for_tui, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {}", e)))?;
    Ok(())
}

fn cmd_serve_outer(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keyring::Keyring;

    debug!(relay, headless, "starting server from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        let decrypted = secret_bytes.as_slice()?;
        secret.copy_from_slice(&decrypted);
        keyring.load_key(record.pubkey, secret, record.key_type, record.name)?;
        secret.zeroize();
    }

    let keyring = Arc::new(Mutex::new(keyring));
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    if headless {
        rt.block_on(async {
            let mut server = Server::new(keyring, relay, None).await?;
            info!(relay, bunker_url = %server.bunker_url(), "server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub) = rt.block_on(async {
        let server = Server::new(keyring.clone(), relay, None).await?;
        Ok::<_, KeepError>((
            server.bunker_url(),
            server.pubkey().to_bech32().unwrap_or_default(),
        ))
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "runtime error", false)
                        .with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let mut server =
                match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {}", e)))?;
    Ok(())
}

fn cmd_serve_hidden(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keyring::Keyring;

    debug!(relay, headless, "starting server from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    out.hidden_label();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        let decrypted = secret_bytes.as_slice()?;
        secret.copy_from_slice(&decrypted);
        keyring.load_key(record.pubkey, secret, record.key_type, record.name)?;
        secret.zeroize();
    }

    let keyring = Arc::new(Mutex::new(keyring));
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    if headless {
        rt.block_on(async {
            let mut server = Server::new(keyring, relay, None).await?;
            info!(relay, bunker_url = %server.bunker_url(), "hidden server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub) = rt.block_on(async {
        let server = Server::new(keyring.clone(), relay, None).await?;
        Ok::<_, KeepError>((
            server.bunker_url(),
            server.pubkey().to_bech32().unwrap_or_default(),
        ))
    })?;

    info!(relay, npub = %npub, "starting TUI for hidden volume");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "runtime error", false)
                        .with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let mut server =
                match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {}", e)))?;
    Ok(())
}
