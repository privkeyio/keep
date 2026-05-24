use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Mutex as StdMutex;

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

use keep_core::Keep;

/// Shared application state handed to every axum handler.
#[derive(Clone)]
pub struct AppState {
    /// Unlocked vault, used for read-only queries (share listing, etc.).
    pub keep: std::sync::Arc<Mutex<Keep>>,
    /// Bunker connection details, populated once the server is up.
    pub bunker: BunkerInfo,
    /// Live event stream (logs + approval requests) for WebSocket clients.
    pub events: broadcast::Sender<Event>,
    /// Pending approval requests awaiting a browser decision, keyed by id.
    pub approvals: std::sync::Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
}

#[derive(Clone, Serialize)]
pub struct BunkerInfo {
    /// "network-frost" (always-on co-signer) or "single-key" (fallback).
    pub mode: String,
    pub url: String,
    pub npub: String,
    /// NIP-46 bunker transport relay.
    pub relay: String,
    /// FROST peer-coordination relays (network mode only).
    pub frost_relays: Vec<String>,
    /// Group npub this node co-signs for (network mode only).
    pub group: Option<String>,
    /// Threshold as "t-of-n" (network mode only).
    pub threshold: Option<String>,
}

/// An event pushed to connected WebSocket clients.
#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Log {
        app: String,
        action: String,
        success: bool,
        detail: Option<String>,
    },
    Approval {
        id: u64,
        app: String,
        method: String,
        kind: Option<u16>,
        preview: Option<String>,
    },
}
