mod api;
mod bunker;
mod state;
mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::{broadcast, Mutex};
use tower_http::services::{ServeDir, ServeFile};

use keep_core::Keep;

use crate::state::{AppState, BunkerInfo};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_relays(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Resolve the FROST group to co-sign for: an explicit npub, else the single
/// group present in the vault. Returns `None` (→ setup mode) when there is no
/// share yet or the choice is ambiguous.
// `Ok(None)` means genuine first-run (no shares → setup mode); `Err` means
// misconfiguration (bad KEEP_FROST_GROUP, or multiple groups with no choice)
// and is fatal so the operator sees the problem instead of a silent setup mode.
fn resolve_group(
    keep: &Keep,
    explicit: Option<&str>,
) -> Result<Option<([u8; 32], String)>, String> {
    if let Some(npub) = explicit {
        let bytes = keep_core::keys::npub_to_bytes(npub)
            .map_err(|e| format!("invalid KEEP_FROST_GROUP npub: {e}"))?;
        return Ok(Some((bytes, npub.to_string())));
    }
    let shares = match keep.frost_list_shares() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "frost_list_shares failed; treating as no shares");
            Vec::new()
        }
    };
    let mut groups: Vec<[u8; 32]> = shares.iter().map(|s| s.metadata.group_pubkey).collect();
    groups.sort();
    groups.dedup();
    match groups.as_slice() {
        [g] => Ok(Some((*g, keep_core::keys::bytes_to_npub(g)))),
        [] => Ok(None),
        _ => Err(format!(
            "multiple FROST groups present ({}); set KEEP_FROST_GROUP to choose one",
            groups.len()
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    keep_frost_net::install_default_crypto_provider();

    let vault_path = PathBuf::from(env_or("KEEP_PATH", "/data"));
    let bunker_relays = parse_relays(&env_or(
        "KEEP_BUNKER_RELAY",
        &env_or("KEEP_RELAY", "wss://relay.damus.io"),
    ));
    let frost_group = std::env::var("KEEP_FROST_GROUP").ok();
    let auto_approve = env_or("KEEP_FROST_AUTO_APPROVE", "true") != "false";
    let ui_dir = PathBuf::from(env_or("KEEP_WEB_UI_DIR", "ui/dist"));
    let listen: SocketAddr = env_or("KEEP_WEB_LISTEN", "0.0.0.0:8080").parse()?;
    let password = std::env::var("KEEP_PASSWORD")
        .map_err(|_| "KEEP_PASSWORD must be set for headless unlock")?;

    // First-run provisioning: create the vault if this is a fresh install
    // (e.g. first StartOS boot) rather than crashing.
    let mut keep = match Keep::open(&vault_path) {
        Ok(k) => k,
        Err(keep_core::error::KeepError::NotFound(_)) => {
            tracing::info!(path = %vault_path.display(), "no vault found; creating");
            Keep::create(&vault_path, &password)?
        }
        Err(e) => return Err(e.into()),
    };
    keep.unlock(&password)?;
    tracing::info!(path = %vault_path.display(), "vault unlocked");

    let (events, _) = broadcast::channel(256);
    let approvals = Arc::new(StdMutex::new(HashMap::new()));
    // Kill switch shared with the co-signer policy; starts from the env default.
    let signing_enabled = Arc::new(std::sync::atomic::AtomicBool::new(auto_approve));

    // Resolve which FROST group this node co-signs for: an explicit
    // KEEP_FROST_GROUP, otherwise the single group present in the vault.
    // Auto-resolution avoids the chicken-and-egg of needing the group npub
    // before the share has been imported.
    let resolved_group = resolve_group(&keep, frost_group.as_deref())?;

    let allow_single_key = env_or("KEEP_ALLOW_SINGLE_KEY", "false") == "true";

    let mut node = None;
    let bunker_info = if let Some((group_pubkey, group_npub)) = resolved_group {
        match keep.frost_get_share(&group_pubkey) {
            Ok(share) => {
                let frost_relays = parse_relays(&env_or("KEEP_FROST_RELAY", ""));
                let frost_relays = if frost_relays.is_empty() {
                    bunker_relays.clone()
                } else {
                    frost_relays
                };
                let handle = bunker::spawn_network_frost(
                    bunker::NetworkConfig {
                        share,
                        group_pubkey,
                        group_npub,
                        frost_relays,
                        bunker_relays,
                        enabled: signing_enabled.clone(),
                    },
                    events.clone(),
                    approvals.clone(),
                )
                .map_err(|e| format!("failed to start co-signer: {e}"))?;
                node = Some(handle.node);
                handle.info
            }
            Err(_) => {
                tracing::warn!(group = %group_npub, "group configured but no share present; setup mode");
                BunkerInfo::setup()
            }
        }
    } else if allow_single_key && keep.keyring().get_primary().is_some() {
        // Explicit opt-in: sign with the vault's primary key alone (no
        // threshold security — the full key lives on this box).
        tracing::warn!("KEEP_ALLOW_SINGLE_KEY set; single-key bunker (no threshold security)");
        // Transfer ownership of the keyring into the bunker thread; `keep`'s
        // keyring is intentionally left empty afterwards (the bunker is the
        // only thing that signs in this mode — don't read keep.keyring() below).
        let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
        let relay = bunker_relays.first().cloned().unwrap_or_default();
        bunker::spawn_single_key(keyring, relay, events.clone(), approvals.clone())
            .map_err(|e| format!("failed to start bunker: {e}"))?
    } else {
        // Nothing to sign with yet: serve the admin UI so the operator can
        // import a share, then restart the service to start the co-signer.
        tracing::info!("no FROST share available; serving in setup mode");
        BunkerInfo::setup()
    };
    let keep = Arc::new(Mutex::new(keep));
    tracing::info!(mode = %bunker_info.mode, "started");

    let state = AppState {
        keep,
        bunker: bunker_info,
        events,
        approvals,
        signing_enabled,
        node,
    };

    let serve_index = ServeFile::new(ui_dir.join("index.html"));
    let static_files = ServeDir::new(&ui_dir).fallback(serve_index);

    let app = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/bunker", get(api::bunker))
        .route("/api/shares", get(api::shares))
        .route("/api/shares/import", post(api::import_share))
        .route("/api/shares/export", post(api::export_share))
        .route("/api/shares/delete", post(api::delete_share))
        .route("/api/shares/rename", post(api::rename_share))
        .route("/api/signing-log", get(api::signing_log))
        .route(
            "/api/killswitch",
            get(api::killswitch_status).post(api::set_killswitch),
        )
        .route("/api/approvals/{id}", post(api::resolve_approval))
        .route("/api/events", get(ws::events))
        .fallback_service(static_files)
        .with_state(state);

    tracing::info!(%listen, "serving web admin");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
