use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    /// Latched once the operator deletes the share the live node loaded. The
    /// node still holds that share in memory, so co-signing is force-disabled
    /// and cannot be re-enabled until a restart re-resolves shares from disk.
    pub signer_retired: Arc<AtomicBool>,
    /// Where the kill-switch state is persisted, so a live toggle survives a
    /// restart instead of reverting to a boot default.
    pub signing_flag_path: PathBuf,
    /// The running FROST node (network mode only), for reading the signing
    /// audit log and peer state.
    pub node: Option<Arc<KfpNode>>,
    /// Single-flight latch for active-group switches. Once a switch is claimed,
    /// the node is on its way to exiting/restarting, so a second concurrent
    /// switch is rejected rather than racing to persist a different key.
    pub switching: Arc<AtomicBool>,
}

#[derive(Clone, Serialize)]
pub struct BunkerInfo {
    /// "network-frost" (always-on co-signer) or "single-key" (fallback).
    pub mode: String,
    pub url: String,
    pub npub: String,
    /// NIP-46 bunker transport relays.
    pub bunker_relays: Vec<String>,
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
            bunker_relays: Vec::new(),
            frost_relays: Vec::new(),
            group: None,
            threshold: None,
        }
    }
}

/// File (inside the vault dir) holding the persisted kill-switch state.
pub fn signing_flag_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("signing_enabled")
}

/// Reads the persisted kill-switch state, or `None` if it was never set or is
/// unreadable (caller falls back to the boot default).
pub fn read_signing_flag(path: &Path) -> Option<bool> {
    match std::fs::read_to_string(path) {
        Ok(s) => match s.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Persists the kill-switch state so it survives a restart. Best-effort: a write
/// failure is logged, not surfaced, since the in-memory toggle still applies.
pub fn persist_signing_flag(path: &Path, enabled: bool) {
    if let Err(e) = std::fs::write(path, if enabled { "true" } else { "false" }) {
        tracing::warn!(error = %e, path = %path.display(), "failed to persist kill-switch state");
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a credential file, creating it `0600` on Unix. Propagates IO errors:
/// a credential that can't be persisted must fail startup, not silently rotate.
///
/// Writes to a sibling temp file, fsyncs, then atomically renames over the
/// target, so a crash mid-write cannot leave a truncated/empty credential that a
/// later boot would treat as missing and silently replace.
fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    // Per-write temp name (PID + random suffix) so a concurrent writer cannot
    // clobber an in-flight temp file before its rename.
    let suffix: [u8; 8] = keep_core::crypto::random_bytes();
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), to_hex(&suffix)));

    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };

    // On any failure before the rename succeeds, remove the temp so a crash or
    // transient error cannot leave an unguessable, never-cleaned-up temp file.
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // fsync the parent directory so the rename itself is durable across a crash;
    // otherwise the file could survive while the directory entry is lost.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Loads the persisted NIP-46 bunker secret, generating and storing one (`0600`)
/// on first run. Must be stable so the advertised bunker URL (which embeds it)
/// doesn't change across restarts. A write failure is propagated so startup
/// fails rather than rotating to an ephemeral secret that breaks saved clients.
pub fn load_or_create_bunker_secret(vault_dir: &Path) -> std::io::Result<String> {
    let path = vault_dir.join("bunker_secret");
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                // The file exists but is empty (e.g. a truncated write): fail
                // closed rather than mint a new secret that would change the
                // advertised bunker URL and break saved client connections.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bunker_secret file is empty; refusing to rotate credential",
                ));
            }
            Ok(trimmed.to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let bytes: [u8; 16] = keep_core::crypto::random_bytes();
            let secret = to_hex(&bytes);
            write_secret_file(&path, &secret)?;
            Ok(secret)
        }
        Err(e) => Err(e),
    }
}

/// Loads the persisted NIP-46 transport key (the bunker URL's own identity),
/// generating and storing one (`0600`) on first run. Must be stable so the
/// bunker URL's pubkey doesn't change across restarts and saved client
/// connections keep working.
pub fn load_or_create_transport_key(vault_dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = vault_dir.join("bunker_transport_key");
    match std::fs::read_to_string(&path) {
        Ok(s) => decode_hex32(s.trim()).ok_or_else(|| {
            // The file exists but is malformed (e.g. a truncated write): fail
            // closed rather than mint a new key that would change the bunker
            // URL's pubkey and break saved client connections.
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bunker_transport_key file is malformed; refusing to rotate identity",
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let bytes: [u8; 32] = keep_core::crypto::random_bytes();
            let hex = to_hex(&bytes);
            write_secret_file(&path, &hex)?;
            Ok(bytes)
        }
        Err(e) => Err(e),
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
