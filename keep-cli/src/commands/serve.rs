// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use nostr_sdk::prelude::ToBech32;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;
use keep_nip46::types::{ApprovalRequest, LogEvent, ServerCallbacks};
use keep_nip46::{FrostSigner, NetworkFrostSigner, Server, ServerConfig};

use crate::output::Output;
use crate::tui::{ApprovalRequest as TuiApprovalRequest, LogEntry, TuiEvent};

use super::{get_password, is_hidden_vault};

struct TuiCallbacks {
    tx: Sender<TuiEvent>,
}

impl ServerCallbacks for TuiCallbacks {
    fn on_log(&self, event: LogEvent) {
        let _ = self.tx.send(TuiEvent::Log(
            LogEntry::new(&event.app, &event.action, event.success)
                .with_detail(event.detail.as_deref().unwrap_or("")),
        ));
    }

    fn request_approval(&self, request: ApprovalRequest) -> bool {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let tui_req = TuiApprovalRequest {
            id: 0,
            app: request.app_name,
            action: request.method,
            kind: request.event_kind.map(|k| k.as_u16()),
            content_preview: request.event_content,
            response_tx,
        };

        if self.tx.send(TuiEvent::Approval(tui_req)).is_err() {
            return false;
        }
        response_rx.recv().unwrap_or(false)
    }
}

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
        out.field("Threshold", &format!("{threshold}-of-{total_shares}"));
        out.field("FROST Relay", frost_relay);
        out.field("Bunker Relay", relay);
        out.newline();

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

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

            let frost_config = if headless {
                ServerConfig {
                    auto_approve: true,
                    ..ServerConfig::default()
                }
            } else {
                ServerConfig::default()
            };
            let mut server = Server::new_network_frost_with_config(
                net_signer,
                transport_key,
                &[relay.to_string()],
                None,
                frost_config,
            )
            .await?;
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
                    out.info(&format!("Using FROST signing ({threshold}-of-{total})"));
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
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    if headless {
        let headless_config = ServerConfig {
            auto_approve: true,
            ..Default::default()
        };
        rt.block_on(async {
            let mut server = if let Some(frost) = frost_signer {
                let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
                Server::new_with_config(
                    Arc::new(Mutex::new(keep_core::keyring::Keyring::new())),
                    Some(frost),
                    Some(transport_key),
                    relay,
                    None,
                    headless_config,
                )
                .await?
            } else {
                Server::new_with_config(keyring, None, None, relay, None, headless_config).await?
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
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "runtime error", false).with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let callbacks: Option<Arc<dyn ServerCallbacks>> = Some(Arc::new(TuiCallbacks {
                tx: tui_tx_clone.clone(),
            }));

            let mut server =
                if let (Some(frost), Some(transport_key)) = (frost_signer, transport_key_for_tui) {
                    match Server::new_frost(frost, transport_key, &relay_clone, callbacks).await {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = tui_tx_clone.send(TuiEvent::Log(
                                LogEntry::new("system", "server error", false)
                                    .with_detail(&e.to_string()),
                            ));
                            return;
                        }
                    }
                } else {
                    match Server::new(keyring_for_tui, &relay_clone, callbacks).await {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = tui_tx_clone.send(TuiEvent::Log(
                                LogEntry::new("system", "server error", false)
                                    .with_detail(&e.to_string()),
                            ));
                            return;
                        }
                    }
                };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {e}")))?;
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
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    if headless {
        rt.block_on(async {
            let mut server = Server::new_with_config(
                keyring,
                None,
                None,
                relay,
                None,
                ServerConfig {
                    auto_approve: true,
                    ..Default::default()
                },
            )
            .await?;
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
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "runtime error", false).with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let callbacks: Option<Arc<dyn ServerCallbacks>> = Some(Arc::new(TuiCallbacks {
                tx: tui_tx_clone.clone(),
            }));

            let mut server = match Server::new(keyring, &relay_clone, callbacks).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tui_tx_clone.send(TuiEvent::Log(
                        LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                    ));
                    return;
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {e}")))?;
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
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    if headless {
        rt.block_on(async {
            let mut server = Server::new_with_config(
                keyring,
                None,
                None,
                relay,
                None,
                ServerConfig {
                    auto_approve: true,
                    ..Default::default()
                },
            )
            .await?;
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
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "runtime error", false).with_detail(&e.to_string()),
                ));
                return;
            }
        };
        rt.block_on(async {
            let callbacks: Option<Arc<dyn ServerCallbacks>> = Some(Arc::new(TuiCallbacks {
                tx: tui_tx_clone.clone(),
            }));

            let mut server = match Server::new(keyring, &relay_clone, callbacks).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tui_tx_clone.send(TuiEvent::Log(
                        LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                    ));
                    return;
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(TuiEvent::Log(
                    LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run()
        .map_err(|e| KeepError::Runtime(format!("TUI: {e}")))?;
    Ok(())
}
