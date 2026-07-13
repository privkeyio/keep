// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Local inspect socket so read-only CLI commands can coexist with a running
//! `keep serve` daemon that holds redb's exclusive writer lock (#533).
//!
//! redb opens the vault file with an exclusive lock, so a second `Keep::open`
//! fails while the daemon runs. Instead of failing, read-only commands connect
//! to a per-vault Unix socket the daemon serves and get the (metadata-only)
//! answer from the daemon's already-open, unlocked vault.
//!
//! Security: the socket is created mode `0600` inside the (0700, owner-only)
//! vault directory, so only processes running as the vault owner can connect.
//! The daemon answers ONLY read-only, metadata-only requests (key name, kind,
//! npub) and NEVER returns secret key material.
//!
//! Trust model note: unlike a direct `keep list`, the socket path returns
//! metadata WITHOUT the vault password. This lowers the bar for reading key
//! names/npubs from "knows the password" to "is the same Unix user" while a
//! daemon runs. That is acceptable because the daemon already holds the unlocked
//! keyring in memory, which a same-user attacker can recover regardless; the
//! socket exposes strictly less (metadata only, no secrets).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use keep_core::error::{KeepError, Result};
use keep_core::keyring::Keyring;

/// Filename of the per-vault inspect socket, inside the vault directory.
const SOCKET_NAME: &str = "keep.sock";
/// Upper bound on a request/response line, a cheap guard against a runaway or
/// hostile (same-user) peer streaming bytes without a newline.
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
/// Drop a connection whose request does not arrive promptly (slowloris guard).
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Cap on concurrent in-flight connections, so a burst cannot pile up tasks/FDs.
const MAX_CONNECTIONS: usize = 32;

/// Path of the inspect socket for a vault.
pub(crate) fn inspect_socket_path(vault: &Path) -> PathBuf {
    vault.join(SOCKET_NAME)
}

#[derive(Serialize, Deserialize)]
struct InspectRequest {
    cmd: String,
}

/// One key's non-secret metadata, mirroring what `keep list` renders.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KeyInfo {
    pub name: String,
    pub key_type: String,
    pub npub: String,
}

#[derive(Serialize, Deserialize, Default)]
struct InspectResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Snapshot the keyring's non-secret key metadata (name, kind, npub). Never
/// touches secret material.
fn list_keys(keyring: &Keyring) -> Vec<KeyInfo> {
    keyring
        .list()
        .map(|slot| KeyInfo {
            name: slot.name.clone(),
            key_type: format!("{:?}", slot.key_type),
            npub: keep_core::keys::bytes_to_npub(&slot.pubkey),
        })
        .collect()
}

/// Serve the inspect socket for `vault`, answering read-only requests from the
/// shared `keyring`, until the task is dropped/aborted. Binds `0600` and clears
/// any stale socket first. Returns only on a bind error.
pub(crate) async fn serve_inspect_socket(
    vault: &Path,
    keyring: Arc<Mutex<Keyring>>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let sock = inspect_socket_path(vault);
    // A leftover socket from a crashed daemon would block bind; the writer lock
    // proves no live daemon owns it, so removing it is safe.
    let _ = std::fs::remove_file(&sock);
    let listener = tokio::net::UnixListener::bind(&sock)?;
    // Owner-only. The vault dir is itself restrictive, so the window between bind
    // and chmod is not reachable by another user in practice.
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;

    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _addr) = listener.accept().await?;
        // Backpressure: never hold more than MAX_CONNECTIONS handlers at once.
        let Ok(permit) = Arc::clone(&limit).acquire_owned().await else {
            break; // semaphore closed
        };
        let keyring = Arc::clone(&keyring);
        tokio::spawn(async move {
            let _ = handle_conn(stream, keyring).await;
            drop(permit);
        });
    }
    Ok(())
}

async fn handle_conn(
    mut stream: tokio::net::UnixStream,
    keyring: Arc<Mutex<Keyring>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (rd, mut wr) = stream.split();
    let mut reader = BufReader::new(rd).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    // Bounded (MAX_REQUEST_BYTES via take) and time-bounded: a client that never
    // sends a newline is dropped rather than parking the task.
    if tokio::time::timeout(READ_TIMEOUT, reader.read_line(&mut line))
        .await
        .is_err()
    {
        return Ok(());
    }

    let response = match serde_json::from_str::<InspectRequest>(line.trim()) {
        Ok(req) if req.cmd == "list" => {
            let keys = {
                let kr = keyring.lock().await;
                list_keys(&kr)
            };
            InspectResponse {
                keys: Some(keys),
                error: None,
            }
        }
        Ok(req) => InspectResponse {
            keys: None,
            error: Some(format!("unsupported inspect command: {}", req.cmd)),
        },
        Err(_) => InspectResponse {
            keys: None,
            error: Some("malformed inspect request".into()),
        },
    };

    let mut bytes = serde_json::to_vec(&response).unwrap_or_default();
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;
    wr.flush().await?;
    Ok(())
}

/// Ask a running daemon for its key list over the inspect socket. Used by
/// `keep list` when `Keep::open` reports the vault is already open.
pub(crate) fn query_list(vault: &Path) -> Result<Vec<KeyInfo>> {
    use std::io::{BufRead, BufReader, Write};
    use std::time::Duration;

    let sock = inspect_socket_path(vault);
    let mut stream = std::os::unix::net::UnixStream::connect(&sock).map_err(|e| {
        KeepError::Runtime(format!(
            "the vault is held by a daemon, but its inspect socket {} is unreachable: {e}",
            sock.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| KeepError::Runtime(format!("set socket timeout: {e}")))?;

    let mut request = serde_json::to_vec(&InspectRequest { cmd: "list".into() })
        .map_err(|e| KeepError::Runtime(format!("encode request: {e}")))?;
    request.push(b'\n');
    stream
        .write_all(&request)
        .map_err(|e| KeepError::Runtime(format!("write to inspect socket: {e}")))?;

    let mut line = String::new();
    // Bound the response too: a malicious (same-user) socket cannot grow this
    // unboundedly. `set_read_timeout` above bounds a hang; `take` bounds volume.
    BufReader::new(std::io::Read::take(&stream, MAX_REQUEST_BYTES))
        .read_line(&mut line)
        .map_err(|e| KeepError::Runtime(format!("read from inspect socket: {e}")))?;
    let response: InspectResponse = serde_json::from_str(line.trim())
        .map_err(|e| KeepError::Runtime(format!("decode inspect response: {e}")))?;
    if let Some(err) = response.error {
        return Err(KeepError::Runtime(format!(
            "daemon rejected request: {err}"
        )));
    }
    Ok(response.keys.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::keys::KeyType;

    #[tokio::test]
    async fn inspect_socket_round_trips_key_metadata() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault = dir.path().to_path_buf();

        // A keyring with one loaded key, as the daemon would hold post-unlock.
        let keyring = {
            let mut kr = Keyring::new();
            kr.load_key([9u8; 32], [7u8; 32], KeyType::Nostr, "alpha".to_string())
                .unwrap();
            Arc::new(Mutex::new(kr))
        };

        let vault_for_server = vault.clone();
        let server = tokio::spawn(async move {
            let _ = serve_inspect_socket(&vault_for_server, keyring).await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let vault_for_client = vault.clone();
        let keys = tokio::task::spawn_blocking(move || query_list(&vault_for_client))
            .await
            .unwrap()
            .expect("query_list");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "alpha");
        assert_eq!(keys[0].key_type, "Nostr");
        assert!(keys[0].npub.starts_with("npub1"));

        server.abort();
    }

    #[test]
    fn query_list_errors_when_no_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        // No server bound: connecting must fail with a clear message.
        let err = query_list(dir.path()).unwrap_err();
        assert!(err.to_string().contains("inspect socket"));
    }
}
