// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
use crate::types::{LogEvent, ServerCallbacks};

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
        cb.on_connect(&client_id, &client_id);
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
        buf.clear();
        let mut total = 0usize;
        let too_large = loop {
            let fill = tokio::time::timeout(IDLE_TIMEOUT, reader.fill_buf()).await;
            let available = match fill {
                Err(_) => {
                    info!(client = %client_id, "idle timeout, disconnecting");
                    handler.revoke_client(&app_pubkey).await;
                    return Ok(());
                }
                Ok(Ok([])) => {
                    if total == 0 {
                        handler.revoke_client(&app_pubkey).await;
                        info!(client = %client_id, "local client disconnected");
                        return Ok(());
                    }
                    break false;
                }
                Ok(Ok(b)) => b,
                Ok(Err(_)) => {
                    handler.revoke_client(&app_pubkey).await;
                    return Ok(());
                }
            };
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..pos]);
                reader.consume(pos + 1);
                break buf.len() > max_size;
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
                break true;
            }
            buf.extend_from_slice(available);
            reader.consume(len);
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
        let line = match std::str::from_utf8(&buf) {
            Ok(s) => s,
            Err(_) => {
                reply_or_disconnect!(&mut write_half, br#"{"id":"","error":"invalid request"}"#);
                continue;
            }
        };

        let request: crate::types::Nip46Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                reply_or_disconnect!(&mut write_half, br#"{"id":"","error":"invalid JSON"}"#);
                continue;
            }
        };

        if request.id.len() > 64
            || !request
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            reply_or_disconnect!(
                &mut write_half,
                br#"{"id":"","error":"invalid request ID"}"#
            );
            continue;
        }

        const MAX_NIP46_PARAMS: usize = 10;
        if request.params.len() > MAX_NIP46_PARAMS {
            reply_or_disconnect!(
                &mut write_half,
                br#"{"id":"","error":"too many request params"}"#
            );
            continue;
        }

        let method = request.method.clone();
        let response = dispatch_request(&handler, user_pubkey, app_pubkey, request, max_size).await;

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
