// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::{info, warn};

use keep_core::error::{KeepError, NetworkError, Result};
use keep_core::keyring::Keyring;

use crate::audit::AuditLog;
use crate::handler::SignerHandler;
use crate::permissions::PermissionManager;
use crate::rate_limit::RateLimitConfig;
use crate::server::dispatch_request;
use crate::types::{ConnectAuthorization, LogEvent, ServerCallbacks};

const MAX_CONNECTIONS: usize = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub struct LocalServerConfig {
    pub max_request_json_size: usize,
    pub rate_limit: Option<RateLimitConfig>,
    pub kill_switch: Option<Arc<AtomicBool>>,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            max_request_json_size: 64 * 1024,
            rate_limit: None,
            kill_switch: None,
        }
    }
}

pub struct LocalServer {
    handler: Arc<SignerHandler>,
    socket_path: PathBuf,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    max_request_size: usize,
}

impl LocalServer {
    pub fn new(
        keyring: Arc<Mutex<Keyring>>,
        socket_path: PathBuf,
        callbacks: Option<Arc<dyn ServerCallbacks>>,
        config: LocalServerConfig,
    ) -> Result<Self> {
        let permissions = Arc::new(Mutex::new(PermissionManager::new()));
        let audit = Arc::new(Mutex::new(AuditLog::new(10_000)));
        let mut handler = SignerHandler::new(keyring, permissions, audit, callbacks.clone());
        if let Some(ref rl) = config.rate_limit {
            handler = handler.with_rate_limit(rl.clone());
        }
        if let Some(ks) = config.kill_switch {
            handler = handler.with_kill_switch(ks);
        }
        Ok(Self {
            handler: Arc::new(handler),
            socket_path,
            callbacks,
            max_request_size: config.max_request_json_size,
        })
    }

    pub fn handler(&self) -> Arc<SignerHandler> {
        self.handler.clone()
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn pseudo_pubkey_for(client_id: &str) -> PublicKey {
        let hash = Sha256::digest(client_id.as_bytes());
        let mut bytes: [u8; 32] = hash.into();
        loop {
            if let Ok(sk) = nostr_sdk::secp256k1::SecretKey::from_slice(&bytes) {
                return Keys::new(sk.into()).public_key();
            }
            bytes[0] = bytes[0].wrapping_add(1);
        }
    }

    pub async fn run(self) -> Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(parent) = self.socket_path.parent() {
            #[cfg(unix)]
            {
                use std::fs::DirBuilder;
                use std::os::unix::fs::DirBuilderExt;
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(KeepError::Io)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(parent).map_err(KeepError::Io)?;
        }

        let listener = tokio::net::UnixListener::bind(&self.socket_path)
            .map_err(|e| NetworkError::relay(format!("bind socket: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))
                .map_err(KeepError::Io)?;
        }

        info!(path = %self.socket_path.display(), "local signer listening");

        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _addr) = result
                        .map_err(|e| NetworkError::relay(format!("accept: {e}")))?;

                    if connections.len() >= MAX_CONNECTIONS {
                        warn!("max connections ({MAX_CONNECTIONS}) reached, rejecting");
                        drop(stream);
                        continue;
                    }

                    #[cfg(unix)]
                    if let Ok(cred) = stream.peer_cred() {
                        info!(pid = ?cred.pid(), uid = ?cred.uid(), "local client connecting");
                    }

                    let handler = self.handler.clone();
                    let callbacks = self.callbacks.clone();
                    let max_size = self.max_request_size;

                    connections.spawn(async move {
                        if let Err(e) = handle_connection(stream, handler, callbacks, max_size).await {
                            warn!(error = %e, "local client connection error");
                        }
                    });
                }
                Some(_) = connections.join_next() => {}
            }
        }
    }
}

fn next_client_id() -> String {
    let id: u128 = rand::random();
    format!("local-{id:032x}")
}

async fn write_line(w: &mut OwnedWriteHalf, data: &[u8]) -> std::io::Result<()> {
    w.write_all(data).await?;
    w.write_all(b"\n").await
}

/// Outcome of reading one newline-delimited request frame from a client.
enum FrameOutcome {
    /// A complete frame is in `buf`; `too_large` if it exceeded `max_size`.
    Line { too_large: bool },
    /// No data for `IDLE_TIMEOUT`.
    IdleTimeout,
    /// Clean EOF with nothing buffered.
    Disconnected,
    /// Underlying read error.
    ReadError,
}

/// Read one `\n`-delimited frame into `buf` (cleared first), enforcing `max_size`.
/// An oversize frame is drained to the next newline so the stream stays aligned;
/// the caller rejects it via the `too_large` flag rather than buffering it.
async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_size: usize,
) -> FrameOutcome {
    buf.clear();
    let mut total = 0usize;
    loop {
        let fill = tokio::time::timeout(IDLE_TIMEOUT, reader.fill_buf()).await;
        let available = match fill {
            Err(_) => return FrameOutcome::IdleTimeout,
            Ok(Ok([])) => {
                if total == 0 {
                    return FrameOutcome::Disconnected;
                }
                return FrameOutcome::Line { too_large: false };
            }
            Ok(Ok(b)) => b,
            Ok(Err(_)) => return FrameOutcome::ReadError,
        };
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return FrameOutcome::Line {
                too_large: buf.len() > max_size,
            };
        }
        let len = available.len();
        total += len;
        if total > max_size {
            reader.consume(len);
            loop {
                let drain = tokio::time::timeout(IDLE_TIMEOUT, reader.fill_buf()).await;
                let rest = match drain {
                    Err(_) => break,
                    Ok(Ok([])) => break,
                    Ok(Ok(b)) => b,
                    Ok(Err(_)) => break,
                };
                if let Some(pos) = rest.iter().position(|&b| b == b'\n') {
                    reader.consume(pos + 1);
                    break;
                }
                let n = rest.len();
                reader.consume(n);
            }
            return FrameOutcome::Line { too_large: true };
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
}

/// Envelope-level validation of a parsed request. Returns the JSON error body to
/// reply with when the request is malformed, or `None` when it is acceptable.
fn validate_request_envelope(request: &crate::types::Nip46Request) -> Option<&'static [u8]> {
    const MAX_NIP46_PARAMS: usize = 10;
    if request.id.len() > 64
        || !request
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Some(br#"{"id":"","error":"invalid request ID"}"#);
    }
    if request.params.len() > MAX_NIP46_PARAMS {
        return Some(br#"{"id":"","error":"too many request params"}"#);
    }
    None
}

/// Parse and validate one raw request frame. On success returns the parsed
/// request; otherwise returns the JSON error body to reply with (invalid UTF-8,
/// invalid JSON, or a malformed envelope).
fn parse_request(buf: &[u8]) -> std::result::Result<crate::types::Nip46Request, &'static [u8]> {
    let line =
        std::str::from_utf8(buf).map_err(|_| &br#"{"id":"","error":"invalid request"}"#[..])?;
    let request: crate::types::Nip46Request =
        serde_json::from_str(line).map_err(|_| &br#"{"id":"","error":"invalid JSON"}"#[..])?;
    if let Some(err) = validate_request_envelope(&request) {
        return Err(err);
    }
    Ok(request)
}

async fn handle_connection(
    stream: UnixStream,
    handler: Arc<SignerHandler>,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    max_size: usize,
) -> Result<()> {
    let client_id = next_client_id();
    let app_pubkey = LocalServer::pseudo_pubkey_for(&client_id);

    if let Err(e) = handler
        .register_client(app_pubkey, client_id.clone(), Some("get_public_key"))
        .await
    {
        warn!(error = %e, client = %client_id, "failed to register local client");
        return Ok(());
    }

    if let Some(ref cb) = callbacks {
        // Local IPC connections are gated by OS socket permissions, not a per-connect
        // secret or approval prompt, so they are reported as AutoApproved.
        cb.on_connect(&client_id, &client_id, ConnectAuthorization::AutoApproved);
    }

    let user_pubkey = match handler.our_pubkey().await {
        Ok(pk) => pk,
        Err(e) => {
            handler.revoke_client(&app_pubkey).await;
            return Err(KeepError::Runtime(format!("no signing key: {e}")));
        }
    };

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut buf = Vec::with_capacity(1024);

    loop {
        let too_large = match read_frame(&mut reader, &mut buf, max_size).await {
            FrameOutcome::IdleTimeout => {
                info!(client = %client_id, "idle timeout, disconnecting");
                handler.revoke_client(&app_pubkey).await;
                return Ok(());
            }
            FrameOutcome::Disconnected => {
                handler.revoke_client(&app_pubkey).await;
                info!(client = %client_id, "local client disconnected");
                return Ok(());
            }
            FrameOutcome::ReadError => {
                handler.revoke_client(&app_pubkey).await;
                return Ok(());
            }
            FrameOutcome::Line { too_large } => too_large,
        };
        macro_rules! reply_or_disconnect {
            ($w:expr, $data:expr) => {
                if write_line($w, $data).await.is_err() {
                    handler.revoke_client(&app_pubkey).await;
                    return Ok(());
                }
            };
        }

        if too_large {
            reply_or_disconnect!(&mut write_half, br#"{"id":"","error":"request too large"}"#);
            continue;
        }
        let request = match parse_request(&buf) {
            Ok(r) => r,
            Err(err) => {
                reply_or_disconnect!(&mut write_half, err);
                continue;
            }
        };

        let method = request.method.clone();
        // Local IPC authorizes on the socket-accept path above, not on a connect
        // method through dispatch_request, so the connect authorization is ignored here.
        let mut connect_auth = None;
        let response = dispatch_request(
            &handler,
            user_pubkey,
            app_pubkey,
            request,
            max_size,
            &mut connect_auth,
        )
        .await;

        let success = response.error.is_none();
        if let Some(ref cb) = callbacks {
            cb.on_log(LogEvent {
                app: client_id.clone(),
                action: method,
                success,
                detail: response.error.clone(),
            });
        }

        if let Ok(json) = serde_json::to_string(&response) {
            if write_line(&mut write_half, json.as_bytes()).await.is_err() {
                handler.revoke_client(&app_pubkey).await;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // Feed `data` through a duplex stream (writer dropped to signal EOF) and read a
    // single frame, returning the outcome and whatever was buffered.
    async fn read_one(data: &[u8], max_size: usize) -> (FrameOutcome, Vec<u8>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(data).await.unwrap();
        drop(client);
        let mut reader = BufReader::new(server);
        let mut buf = Vec::new();
        let outcome = read_frame(&mut reader, &mut buf, max_size).await;
        (outcome, buf)
    }

    #[tokio::test]
    async fn read_frame_returns_line_without_the_newline() {
        let (outcome, buf) = read_one(b"hello world\n", 1024).await;
        assert!(matches!(outcome, FrameOutcome::Line { too_large: false }));
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn read_frame_flags_oversize_line_terminated_by_newline() {
        let (outcome, _) = read_one(b"abcdefghij\n", 4).await;
        assert!(matches!(outcome, FrameOutcome::Line { too_large: true }));
    }

    #[tokio::test]
    async fn read_frame_flags_oversize_line_with_no_newline_via_drain() {
        let (outcome, _) = read_one(b"abcdefghij", 4).await;
        assert!(matches!(outcome, FrameOutcome::Line { too_large: true }));
    }

    #[tokio::test]
    async fn read_frame_reports_disconnect_on_immediate_eof() {
        let (outcome, buf) = read_one(b"", 1024).await;
        assert!(matches!(outcome, FrameOutcome::Disconnected));
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_frame_treats_unterminated_data_as_a_line_on_eof() {
        let (outcome, buf) = read_one(b"partial", 1024).await;
        assert!(matches!(outcome, FrameOutcome::Line { too_large: false }));
        assert_eq!(buf, b"partial");
    }

    fn req(id: &str, params: Vec<String>) -> crate::types::Nip46Request {
        crate::types::Nip46Request {
            id: id.to_string(),
            method: "get_public_key".to_string(),
            params,
        }
    }

    #[test]
    fn validate_accepts_a_well_formed_envelope() {
        assert!(validate_request_envelope(&req("abc-123", vec![])).is_none());
    }

    #[test]
    fn validate_rejects_overlong_id() {
        let id = "a".repeat(65);
        assert_eq!(
            validate_request_envelope(&req(&id, vec![])),
            Some(&br#"{"id":"","error":"invalid request ID"}"#[..])
        );
    }

    #[test]
    fn validate_rejects_non_alphanumeric_id() {
        assert_eq!(
            validate_request_envelope(&req("bad id!", vec![])),
            Some(&br#"{"id":"","error":"invalid request ID"}"#[..])
        );
    }

    #[test]
    fn validate_rejects_too_many_params() {
        let params = vec!["x".to_string(); 11];
        assert_eq!(
            validate_request_envelope(&req("ok", params)),
            Some(&br#"{"id":"","error":"too many request params"}"#[..])
        );
    }

    #[test]
    fn parse_request_rejects_invalid_utf8() {
        assert_eq!(
            parse_request(&[0xff, 0xfe]).unwrap_err(),
            &br#"{"id":"","error":"invalid request"}"#[..]
        );
    }

    #[test]
    fn parse_request_rejects_invalid_json() {
        assert_eq!(
            parse_request(b"not json").unwrap_err(),
            &br#"{"id":"","error":"invalid JSON"}"#[..]
        );
    }

    #[test]
    fn parse_request_rejects_malformed_envelope() {
        let over = format!(r#"{{"id":"{}","method":"x"}}"#, "a".repeat(65));
        assert_eq!(
            parse_request(over.as_bytes()).unwrap_err(),
            &br#"{"id":"","error":"invalid request ID"}"#[..]
        );
    }

    #[test]
    fn parse_request_accepts_a_valid_frame() {
        let ok = parse_request(br#"{"id":"abc","method":"get_public_key","params":[]}"#);
        assert!(ok.is_ok());
    }
}
