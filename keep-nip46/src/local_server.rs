// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{info, warn};

use keep_core::error::{KeepError, NetworkError, Result};
use keep_core::keyring::Keyring;

use crate::audit::AuditLog;
use crate::handler::SignerHandler;
use crate::permissions::PermissionManager;
use crate::rate_limit::RateLimitConfig;
use crate::server::dispatch_request;
use crate::types::{LogEvent, ServerCallbacks};

static CLIENT_COUNTER: AtomicU64 = AtomicU64::new(1);

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
            std::fs::create_dir_all(parent).map_err(KeepError::Io)?;
        }

        let listener = tokio::net::UnixListener::bind(&self.socket_path)
            .map_err(|e| NetworkError::relay(format!("bind socket: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.socket_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }

        info!(path = %self.socket_path.display(), "local signer listening");

        loop {
            let (stream, _addr) = listener.accept().await
                .map_err(|e| NetworkError::relay(format!("accept: {e}")))?;

            let handler = self.handler.clone();
            let callbacks = self.callbacks.clone();
            let max_size = self.max_request_size;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, handler, callbacks, max_size).await {
                    warn!(error = %e, "local client connection error");
                }
            });
        }
    }
}

fn next_client_id() -> String {
    format!("local-{}", CLIENT_COUNTER.fetch_add(1, Ordering::Relaxed))
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    handler: Arc<SignerHandler>,
    callbacks: Option<Arc<dyn ServerCallbacks>>,
    max_size: usize,
) -> Result<()> {
    let client_id = next_client_id();
    let app_pubkey = LocalServer::pseudo_pubkey_for(&client_id);

    if let Some(ref cb) = callbacks {
        cb.on_connect(&client_id, &client_id);
    }

    let perms = "get_public_key,sign_event,nip44_encrypt,nip44_decrypt,nip04_encrypt,nip04_decrypt";
    if let Err(e) = handler
        .register_client(app_pubkey, client_id.clone(), Some(perms))
        .await
    {
        warn!(error = %e, client = %client_id, "failed to register local client");
        return Ok(());
    }

    let user_pubkey = handler
        .our_pubkey()
        .await
        .map_err(|e| KeepError::Runtime(format!("no signing key: {e}")))?;

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > max_size {
            let err = r#"{"id":"","error":"request too large"}"#;
            let _ = write_half.write_all(err.as_bytes()).await;
            let _ = write_half.write_all(b"\n").await;
            continue;
        }

        let request: crate::types::Nip46Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                let err = r#"{"id":"","error":"invalid JSON"}"#;
                let _ = write_half.write_all(err.as_bytes()).await;
                let _ = write_half.write_all(b"\n").await;
                continue;
            }
        };

        let method = request.method.clone();
        let response = dispatch_request(
            &handler,
            user_pubkey,
            app_pubkey,
            request,
            max_size,
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
            let _ = write_half.write_all(json.as_bytes()).await;
            let _ = write_half.write_all(b"\n").await;
        }
    }

    info!(client = %client_id, "local client disconnected");
    Ok(())
}
