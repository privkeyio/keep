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

use crate::state::AppState;

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

    let mut keep = Keep::open(&vault_path)?;
    keep.unlock(&password)?;
    tracing::info!(path = %vault_path.display(), "vault unlocked");

    let (events, _) = broadcast::channel(256);
    let approvals = Arc::new(StdMutex::new(HashMap::new()));

    let bunker_info = if let Some(group_npub) = frost_group {
        // Always-on network-FROST co-signer: hold one share, coordinate to
        // threshold with peers over the FROST relays.
        let group_pubkey = keep_core::keys::npub_to_bytes(&group_npub)?;
        let share = keep.frost_get_share(&group_pubkey)?;
        let frost_relays = parse_relays(&env_or("KEEP_FROST_RELAY", ""));
        let frost_relays = if frost_relays.is_empty() {
            bunker_relays.clone()
        } else {
            frost_relays
        };
        bunker::spawn_network_frost(
            bunker::NetworkConfig {
                share,
                group_pubkey,
                group_npub,
                frost_relays,
                bunker_relays,
                auto_approve,
            },
            events.clone(),
            approvals.clone(),
        )
        .map_err(|e| format!("failed to start co-signer: {e}"))?
    } else {
        // No FROST group configured: single-key fallback (no threshold
        // security — the full key lives on this box).
        tracing::warn!(
            "no KEEP_FROST_GROUP set; running single-key bunker (no threshold security)"
        );
        let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
        let relay = bunker_relays.first().cloned().unwrap_or_default();
        bunker::spawn_single_key(keyring, relay, events.clone(), approvals.clone())
            .map_err(|e| format!("failed to start bunker: {e}"))?
    };
    let keep = Arc::new(Mutex::new(keep));
    tracing::info!(
        mode = %bunker_info.mode, url = %bunker_info.url, npub = %bunker_info.npub,
        "bunker online"
    );

    let state = AppState {
        keep,
        bunker: bunker_info,
        events,
        approvals,
    };

    let serve_index = ServeFile::new(ui_dir.join("index.html"));
    let static_files = ServeDir::new(&ui_dir).fallback(serve_index);

    let app = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/bunker", get(api::bunker))
        .route("/api/shares", get(api::shares))
        .route("/api/shares/import", post(api::import_share))
        .route("/api/approvals/{id}", post(api::resolve_approval))
        .route("/api/events", get(ws::events))
        .fallback_service(static_files)
        .with_state(state);

    tracing::info!(%listen, "serving web admin");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
