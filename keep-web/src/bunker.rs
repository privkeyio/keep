use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nostr_sdk::prelude::ToBech32;
use tokio::sync::{broadcast, Mutex};

use keep_core::keyring::Keyring;
use keep_nip46::types::{ApprovalRequest, LogEvent, ServerCallbacks};
use keep_nip46::Server;

use crate::state::{BunkerInfo, Event};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Bridges the bunker's signing callbacks onto the web event stream.
///
/// `on_log` fans out to every connected browser; `request_approval` parks the
/// signing thread on a channel until a `POST /api/approvals/:id` resolves it
/// (or it times out), mirroring the desktop approval flow.
struct WebCallbacks {
    events: broadcast::Sender<Event>,
    approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
    next_id: AtomicU64,
}

impl ServerCallbacks for WebCallbacks {
    fn on_log(&self, event: LogEvent) {
        let _ = self.events.send(Event::Log {
            app: event.app,
            action: event.action,
            success: event.success,
            detail: event.detail,
        });
    }

    fn request_approval(&self, request: ApprovalRequest) -> bool {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel();
        if let Ok(mut map) = self.approvals.lock() {
            map.insert(id, tx);
        }

        let _ = self.events.send(Event::Approval {
            id,
            app: request.app_name,
            method: request.method,
            kind: request.event_kind.map(|k| k.as_u16()),
            preview: request.event_content,
        });

        let decision =
            tokio::task::block_in_place(|| rx.recv_timeout(APPROVAL_TIMEOUT).unwrap_or(false));
        if let Ok(mut map) = self.approvals.lock() {
            map.remove(&id);
        }
        decision
    }
}

/// Spawns the NIP-46 bunker on a dedicated thread+runtime (mirroring the CLI
/// `serve` path, where the server is not `Send`) and returns its connection
/// details once it has started.
pub fn spawn(
    keyring: Arc<Mutex<Keyring>>,
    relay: String,
    events: broadcast::Sender<Event>,
    approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
) -> Result<BunkerInfo, String> {
    let (info_tx, info_rx) = channel::<Result<BunkerInfo, String>>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = info_tx.send(Err(format!("tokio runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let callbacks: Arc<dyn ServerCallbacks> = Arc::new(WebCallbacks {
                events,
                approvals,
                next_id: AtomicU64::new(1),
            });
            let mut server =
                match Server::new(keyring, std::slice::from_ref(&relay), Some(callbacks)).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = info_tx.send(Err(format!("bunker start: {e}")));
                        return;
                    }
                };
            let info = BunkerInfo {
                url: server.bunker_url(),
                npub: server.pubkey().to_bech32().unwrap_or_default(),
                relay,
            };
            let _ = info_tx.send(Ok(info));

            if let Err(e) = server.run().await {
                tracing::error!(error = %e, "bunker exited");
            }
        });
    });

    info_rx
        .recv()
        .map_err(|_| "bunker thread terminated before start".to_string())?
}
