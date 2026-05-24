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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    keep_frost_net::install_default_crypto_provider();

    let vault_path = PathBuf::from(env_or("KEEP_PATH", "/data"));
    let relay = env_or("KEEP_RELAY", "wss://relay.damus.io");
    let ui_dir = PathBuf::from(env_or("KEEP_WEB_UI_DIR", "ui"));
    let listen: SocketAddr = env_or("KEEP_WEB_LISTEN", "0.0.0.0:8080").parse()?;
    let password = std::env::var("KEEP_PASSWORD")
        .map_err(|_| "KEEP_PASSWORD must be set for headless unlock")?;

    let mut keep = Keep::open(&vault_path)?;
    keep.unlock(&password)?;
    tracing::info!(path = %vault_path.display(), "vault unlocked");

    // Hand the keyring to the bunker; keep the (now keyring-less) vault for
    // read-only storage queries, exactly as the CLI `serve` path does.
    let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
    let keep = Arc::new(Mutex::new(keep));

    let (events, _) = broadcast::channel(256);
    let approvals = Arc::new(StdMutex::new(HashMap::new()));

    let bunker_info = bunker::spawn(keyring, relay, events.clone(), approvals.clone())
        .map_err(|e| format!("failed to start bunker: {e}"))?;
    tracing::info!(url = %bunker_info.url, npub = %bunker_info.npub, "bunker online");

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
        .route("/api/approvals/{id}", post(api::resolve_approval))
        .route("/api/events", get(ws::events))
        .fallback_service(static_files)
        .with_state(state);

    tracing::info!(%listen, "serving web admin");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
