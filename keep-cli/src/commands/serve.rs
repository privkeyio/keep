// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::ToBech32;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::keyring::Keyring;
use keep_core::keys::bytes_to_npub;
use keep_core::Keep;
use keep_nip46::types::{ApprovalRequest, LogEvent, ServerCallbacks};
use keep_nip46::{FrostSigner, NetworkFrostSigner, Server, ServerConfig};

use crate::output::Output;
use crate::tui::{ApprovalRequest as TuiApprovalRequest, LogEntry, TuiEvent};

use super::{get_password, is_hidden_vault};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

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

    fn request_approval(&self, request: ApprovalRequest) -> keep_nip46::types::ApprovalResult {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let tui_req = TuiApprovalRequest {
            id: 0,
            app: request.app_name,
            action: request.method,
            kind: request.event_kind.map(|k| k.as_u16()),
            content_preview: request.event_content,
            http_auth: request.http_auth.map(|d| (d.url, d.method)),
            response_tx,
        };

        if self.tx.send(TuiEvent::Approval(tui_req)).is_err() {
            return false.into();
        }
        // The TUI does not (yet) capture a remember-duration, so a positive
        // response is one-shot. The new persistent-grant semantics (#575)
        // only apply to bunkers whose callback returns a non-`JustThisTime`
        // `RememberDuration` (today: keep-mobile).
        tokio::task::block_in_place(|| response_rx.recv_timeout(APPROVAL_TIMEOUT).unwrap_or(false))
            .into()
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

        if !headless {
            return Err(KeepError::Runtime(
                "FROST network mode requires --headless".into(),
            ));
        }

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

            let mut server = Server::new_network_frost_with_config(
                net_signer,
                transport_key,
                &[relay.to_string()],
                None,
                ServerConfig {
                    auto_approve: true,
                    ..ServerConfig::default()
                },
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
    let distinct_groups: std::collections::BTreeSet<[u8; 32]> =
        shares.iter().map(|s| s.metadata.group_pubkey).collect();

    if distinct_groups.len() > 1 {
        let mut listing = String::new();
        for g in &distinct_groups {
            listing.push_str("\n  ");
            listing.push_str(&bytes_to_npub(g));
        }
        return Err(KeepError::InvalidInput(format!(
            "vault holds shares for {} distinct FROST groups; pass --frost-group <npub> to choose one:{}",
            distinct_groups.len(),
            listing
        )));
    }

    let (frost_signer, signing_mode, signing_identity) = if !shares.is_empty() {
        let first_group = &shares[0].metadata.group_pubkey;
        let group_shares: Vec<_> = shares
            .iter()
            .filter(|s| &s.metadata.group_pubkey == first_group)
            .cloned()
            .collect();
        let threshold = group_shares[0].metadata.threshold as usize;
        let total = group_shares.len();
        let group_pubkey = *first_group;
        let group_npub = bytes_to_npub(&group_pubkey);
        let mode = format!("FROST {threshold}-of-{total}");
        let signer = if total >= threshold {
            let data_key = keep.data_key()?;
            FrostSigner::new(group_pubkey, group_shares, data_key).ok()
        } else {
            None
        };
        (signer, mode, group_npub)
    } else {
        let primary_npub = keep
            .keyring()
            .get_primary()
            .map(|slot| bytes_to_npub(&slot.pubkey))
            .unwrap_or_else(|| "(no keys)".to_string());
        (None, "Single-key".to_string(), primary_npub)
    };
    out.field("Signing mode", &signing_mode);
    out.field("Signing identity", &signing_identity);

    // Load any NIP-46 client app grants persisted via `keep nip46 grant`.
    // These are loaded into the PermissionManager at startup so headless
    // bunkers don't need to rely on an interactive approval prompt. Only the
    // headless path wires them into the ServerConfig; the interactive TUI path
    // relies on per-request approval, so the banner is scoped to headless mode
    // to avoid misleading the operator.
    let (pre_grants, global_auto_approve) = serve_grants_from_config(
        &keep.get_relay_config_or_default(&keep_core::relay::GLOBAL_RELAY_KEY)?,
    );

    let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    if headless {
        if !pre_grants.is_empty() {
            out.field(
                "Pre-granted apps",
                &format!("{} (from `keep nip46 grant`)", pre_grants.len()),
            );
        }
        // In headless mode `auto_approve` is globally true, so a pre-grant's
        // `auto_approve_kinds` has no additional effect: every signing request
        // from a granted app is auto-approved regardless of kind.
        let headless_config = ServerConfig {
            auto_approve: true,
            pre_grants,
            ..Default::default()
        };
        rt.block_on(async {
            let mut server = if let Some(frost) = frost_signer {
                let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
                Server::new_with_config(
                    Arc::new(Mutex::new(Keyring::new())),
                    Some(frost),
                    Some(transport_key),
                    &[relay.to_string()],
                    None,
                    headless_config,
                )
                .await?
            } else {
                Server::new_with_config(
                    keyring,
                    None,
                    None,
                    &[relay.to_string()],
                    None,
                    headless_config,
                )
                .await?
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

    let (bunker_url, npub, keyring_for_tui, transport_key_for_tui) = rt.block_on(async {
        if let Some(ref frost) = frost_signer {
            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
            let server =
                Server::new_frost(frost.clone(), transport_key, &[relay.to_string()], None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
                Some(transport_key),
            ))
        } else {
            let server = Server::new(keyring.clone(), &[relay.to_string()], None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
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

            // Carry the persisted global auto-approve kinds so the interactive
            // approval prompt skips them, matching `keep nip46 auto-approve`.
            // An unset (empty) list leaves the server's default in place.
            let mut tui_config = ServerConfig::default();
            if !global_auto_approve.is_empty() {
                tui_config.auto_approve_kinds = global_auto_approve;
            }
            let mut server =
                if let (Some(frost), Some(transport_key)) = (frost_signer, transport_key_for_tui) {
                    match Server::new_with_config(
                        Arc::new(Mutex::new(Keyring::new())),
                        Some(frost),
                        Some(transport_key),
                        std::slice::from_ref(&relay_clone),
                        callbacks,
                        tui_config,
                    )
                    .await
                    {
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
                    match Server::new_with_config(
                        keyring_for_tui,
                        None,
                        None,
                        std::slice::from_ref(&relay_clone),
                        callbacks,
                        tui_config,
                    )
                    .await
                    {
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

fn spawn_tui_server(
    keyring: Arc<Mutex<Keyring>>,
    relay: &str,
    bunker_url: String,
    npub: String,
    global_auto_approve: std::collections::HashSet<nostr_sdk::Kind>,
) -> Result<()> {
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

            // Carry the persisted global auto-approve kinds so the interactive
            // approval prompt skips them, matching `keep nip46 auto-approve`.
            // An unset (empty) list leaves the server's default in place.
            let mut tui_config = ServerConfig::default();
            if !global_auto_approve.is_empty() {
                tui_config.auto_approve_kinds = global_auto_approve;
            }

            let mut server = match Server::new_with_config(
                keyring,
                None,
                None,
                std::slice::from_ref(&relay_clone),
                callbacks,
                tui_config,
            )
            .await
            {
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

fn run_headless(
    out: &Output,
    keyring: Arc<Mutex<Keyring>>,
    relay: &str,
    pre_grants: Vec<keep_nip46::PreGrantedApp>,
    global_auto_approve: std::collections::HashSet<nostr_sdk::Kind>,
) -> Result<()> {
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    if !pre_grants.is_empty() {
        out.field(
            "Pre-granted apps",
            &format!("{} (from `keep nip46 grant`)", pre_grants.len()),
        );
    }
    let mut config = ServerConfig {
        auto_approve: true,
        pre_grants,
        ..Default::default()
    };
    if !global_auto_approve.is_empty() {
        config.auto_approve_kinds = global_auto_approve;
    }
    rt.block_on(async {
        let mut server =
            Server::new_with_config(keyring, None, None, &[relay.to_string()], None, config)
                .await?;
        info!(relay, bunker_url = %server.bunker_url(), "server started");
        out.field("Bunker URL", &server.bunker_url());
        out.field("Relay", relay);
        out.newline();
        out.info("Listening...");
        server.run().await
    })?;
    Ok(())
}

fn get_bunker_info(keyring: Arc<Mutex<Keyring>>, relay: &str) -> Result<(String, String)> {
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    rt.block_on(async {
        let server = Server::new(keyring, &[relay.to_string()], None).await?;
        Ok((
            server.bunker_url(),
            server.pubkey().to_bech32().unwrap_or_default(),
        ))
    })
}

fn unlock_hidden_keyring(
    storage: &keep_core::hidden::HiddenStorage,
    data_key: &keep_core::crypto::SecretKey,
) -> Result<Keyring> {
    use keep_core::crypto::{self, EncryptedData};

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
    Ok(keyring)
}

fn cmd_serve_outer(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!(relay, headless, "starting server from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let (pre_grants, global_auto_approve) = serve_grants_from_config(
        &storage.get_relay_config_or_default(&keep_core::relay::GLOBAL_RELAY_KEY)?,
    );

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let keyring = unlock_hidden_keyring(&storage, data_key)?;
    let keyring = Arc::new(Mutex::new(keyring));

    if headless {
        return run_headless(out, keyring, relay, pre_grants, global_auto_approve);
    }

    let (bunker_url, npub) = get_bunker_info(keyring.clone(), relay)?;
    info!(relay, npub = %npub, "starting TUI");
    spawn_tui_server(keyring, relay, bunker_url, npub, global_auto_approve)
}

fn cmd_serve_hidden(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!(relay, headless, "starting server from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    out.hidden_label();

    // Hidden-volume relay-config storage is not yet implemented, so this
    // resolves to an empty grant set: the headless bunker falls back to its
    // built-in `auto_approve` policy. Outer-volume pre-grants are intentionally
    // not loaded on the hidden path so the relay layer never reflects activity
    // tied to the outer volume's identity.
    let (pre_grants, global_auto_approve) = serve_grants_from_config(
        &storage.get_relay_config_or_default(&keep_core::relay::GLOBAL_RELAY_KEY)?,
    );

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let keyring = unlock_hidden_keyring(&storage, data_key)?;
    let keyring = Arc::new(Mutex::new(keyring));

    if headless {
        return run_headless(out, keyring, relay, pre_grants, global_auto_approve);
    }

    let (bunker_url, npub) = get_bunker_info(keyring.clone(), relay)?;
    info!(relay, npub = %npub, "starting TUI for hidden volume");
    spawn_tui_server(keyring, relay, bunker_url, npub, global_auto_approve)
}

/// Translate an already-loaded global `RelayConfig` into the runtime serve
/// grant state: `PreGrantedApp`s populated into the `PermissionManager` so
/// headless bunkers can accept signing requests from previously authorized
/// clients, plus the global auto-approve kinds (`keep nip46 auto-approve`).
/// An empty auto-approve set leaves the server's default in place. Shared by
/// both standard and hidden-vault serve paths from a single config read.
fn serve_grants_from_config(
    cfg: &keep_core::relay::RelayConfig,
) -> (
    Vec<keep_nip46::PreGrantedApp>,
    std::collections::HashSet<nostr_sdk::Kind>,
) {
    let pre_grants = map_stored_to_pregrants(&cfg.bunker_permissions);
    let auto_approve = cfg
        .auto_approve_kinds
        .iter()
        .copied()
        .map(nostr_sdk::Kind::from)
        .collect();
    (pre_grants, auto_approve)
}

/// Pure mapping persisted permissions → runtime `PreGrantedApp`. Separated
/// from the I/O wrapper so the boundary is testable and shared with the
/// desktop's restore path. Malformed pubkeys are skipped (`from_stored`
/// returns `None`); Session/expired Seconds rows are kept here and filtered
/// downstream by `PermissionManager::restore_persisted`, so this stays a
/// pure function of the stored bytes.
fn map_stored_to_pregrants(
    stored: &[keep_core::relay::StoredBunkerPermission],
) -> Vec<keep_nip46::PreGrantedApp> {
    stored
        .iter()
        .filter_map(keep_nip46::PreGrantedApp::from_stored)
        .collect()
}
