use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

use keep_core::Keep;
use keep_frost_net::KfpNode;

/// How long a single-use WebSocket ticket stays valid after issue.
const WS_TICKET_TTL: Duration = Duration::from_secs(30);

/// Single-use, short-lived tickets authorizing one WebSocket upgrade. Browsers
/// can't set headers on a `WebSocket`, so instead of putting the durable bearer
/// token in the URL (where reverse-proxy access logs would capture it), an
/// authed client mints a ticket and passes that; it is consumed on first use.
#[derive(Clone, Default)]
pub struct TicketStore(Arc<StdMutex<HashMap<String, Instant>>>);

impl TicketStore {
    /// Records a freshly minted ticket, pruning any that have expired.
    pub fn issue(&self, ticket: String) {
        if let Ok(mut map) = self.0.lock() {
            let now = Instant::now();
            map.retain(|_, issued| now.duration_since(*issued) < WS_TICKET_TTL);
            map.insert(ticket, now);
        }
    }

    /// Consumes a ticket, returning true only if it was present and unexpired.
    pub fn consume(&self, ticket: &str) -> bool {
        match self.0.lock() {
            Ok(mut map) => map
                .remove(ticket)
                .is_some_and(|issued| issued.elapsed() < WS_TICKET_TTL),
            Err(_) => false,
        }
    }
}

/// Shared application state handed to every axum handler.
#[derive(Clone)]
pub struct AppState {
    /// Unlocked vault, used for read-only queries (share listing, etc.).
    pub keep: Arc<Mutex<Keep>>,
    /// Bunker connection details, populated once the server is up.
    pub bunker: BunkerInfo,
    /// Identifier of the share the running co-signer loaded (network mode), so
    /// the delete guard can block exactly that share without false positives.
    pub active_identifier: Option<u16>,
    /// Live event stream (logs + approval requests) for WebSocket clients.
    pub events: broadcast::Sender<Event>,
    /// Pending approval requests awaiting a browser decision, keyed by id.
    pub approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
    /// Single-use WebSocket upgrade tickets.
    pub ws_tickets: TicketStore,
    /// Kill switch: when false, the co-signer refuses to participate. Toggled
    /// live (no restart); the policy hook reads it on every round.
    pub signing_enabled: Arc<AtomicBool>,
    /// The running FROST node (network mode only), for reading the signing
    /// audit log and peer state.
    pub node: Option<Arc<KfpNode>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_single_use() {
        let store = TicketStore::default();
        store.issue("abc".into());
        assert!(store.consume("abc"));
        // Second use is rejected.
        assert!(!store.consume("abc"));
    }

    #[test]
    fn unknown_ticket_rejected() {
        let store = TicketStore::default();
        assert!(!store.consume("nope"));
        store.issue("abc".into());
        assert!(!store.consume("def"));
    }
}

impl BunkerInfo {
    /// Not yet provisioned: the admin UI is served, but no bunker/co-signer is
    /// running. The operator imports a share, then restarts the service.
    pub fn setup() -> Self {
        Self {
            mode: "setup".into(),
            url: String::new(),
            npub: String::new(),
            relay: String::new(),
            frost_relays: Vec::new(),
            group: None,
            threshold: None,
        }
    }
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
