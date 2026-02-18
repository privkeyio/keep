// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::network::validate_relay_url;
use crate::{KeepMobile, KeepMobileError};
use keep_nip46::types::{ApprovalRequest, LogEvent, ServerCallbacks};
use keep_nip46::{NetworkFrostSigner, RateLimitConfig, Server, ServerConfig};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

const STATUS_STOPPED: u8 = 0;
const STATUS_STARTING: u8 = 1;
const STATUS_RUNNING: u8 = 2;
const STATUS_ERROR: u8 = 3;

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum BunkerStatus {
    Stopped,
    Starting,
    Running,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerLogEvent {
    pub app: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BunkerApprovalRequest {
    pub app_pubkey: String,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ParsedBunkerUrl {
    pub pubkey: String,
    pub relays: Vec<String>,
    pub secret: Option<String>,
}

#[uniffi::export]
pub fn parse_bunker_url(url: &str) -> Result<ParsedBunkerUrl, KeepMobileError> {
    let (pubkey, relays, secret) = keep_nip46::parse_bunker_url(url)
        .map_err(|e| KeepMobileError::InvalidRelayUrl { msg: e })?;
    Ok(ParsedBunkerUrl {
        pubkey: pubkey.to_hex(),
        relays,
        secret,
    })
}

#[uniffi::export(with_foreign)]
pub trait BunkerCallbacks: Send + Sync {
    fn on_log(&self, event: BunkerLogEvent);
    fn request_approval(&self, request: BunkerApprovalRequest) -> bool;
}

struct CallbackBridge {
    callbacks: Arc<dyn BunkerCallbacks>,
}

impl ServerCallbacks for CallbackBridge {
    fn on_log(&self, event: LogEvent) {
        self.callbacks.on_log(BunkerLogEvent {
            app: event.app,
            action: event.action,
            success: event.success,
            detail: event.detail,
        });
    }

    fn request_approval(&self, request: ApprovalRequest) -> bool {
        self.callbacks.request_approval(BunkerApprovalRequest {
            app_pubkey: request.app_pubkey.to_hex(),
            app_name: request.app_name,
            method: request.method,
            event_kind: request.event_kind.map(|k| k.as_u16() as u32),
            event_content: request.event_content,
            requested_permissions: request.requested_permissions,
        })
    }
}

#[derive(uniffi::Object)]
pub struct BunkerHandler {
    mobile: Arc<KeepMobile>,
    status: Arc<AtomicU8>,
    bunker_url: std::sync::Mutex<Option<String>>,
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl BunkerHandler {
    fn set_status(&self, status: u8) {
        self.status.store(status, Ordering::Release);
    }

    fn load_status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }
}

#[uniffi::export]
impl BunkerHandler {
    #[uniffi::constructor]
    pub fn new(mobile: Arc<KeepMobile>) -> Self {
        Self {
            mobile,
            status: Arc::new(AtomicU8::new(STATUS_STOPPED)),
            bunker_url: std::sync::Mutex::new(None),
            shutdown_tx: std::sync::Mutex::new(None),
        }
    }

    pub fn start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
    ) -> Result<(), KeepMobileError> {
        self.do_start_bunker(relays, callbacks, None)
    }

    pub fn start_bunker_with_proxy(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy_host: String,
        proxy_port: u16,
    ) -> Result<(), KeepMobileError> {
        let proxy = crate::network::parse_loopback_proxy(&proxy_host, proxy_port)?;
        self.do_start_bunker(relays, callbacks, Some(proxy))
    }

    pub fn stop_bunker(&self) {
        let tx = self
            .shutdown_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn get_bunker_url(&self) -> Option<String> {
        self.bunker_url
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn get_bunker_status(&self) -> BunkerStatus {
        match self.load_status() {
            STATUS_STARTING => BunkerStatus::Starting,
            STATUS_RUNNING => BunkerStatus::Running,
            STATUS_ERROR => BunkerStatus::Error,
            _ => BunkerStatus::Stopped,
        }
    }
}

impl BunkerHandler {
    fn do_start_bunker(
        &self,
        relays: Vec<String>,
        callbacks: Arc<dyn BunkerCallbacks>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        if relays.is_empty() {
            return Err(KeepMobileError::InvalidRelayUrl {
                msg: "At least one relay required".into(),
            });
        }

        for relay in &relays {
            validate_relay_url(relay)?;
        }

        if self
            .status
            .compare_exchange(
                STATUS_STOPPED,
                STATUS_STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(KeepMobileError::InitializationFailed {
                msg: "Bunker already running or starting".into(),
            });
        }

        let result = self.mobile.runtime.block_on(async {
            let node_guard = self.mobile.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let share_info = self
                .mobile
                .get_share_info()
                .ok_or(KeepMobileError::NotInitialized)?;

            let group_pubkey_bytes: [u8; 32] = hex::decode(&share_info.group_pubkey)
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "Invalid group pubkey hex".into(),
                })?
                .try_into()
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "Invalid group pubkey length".into(),
                })?;

            let network_signer =
                NetworkFrostSigner::with_shared_node(group_pubkey_bytes, Arc::clone(node));

            let transport_secret = keep_core::crypto::random_bytes::<32>();

            let config = ServerConfig {
                rate_limit: Some(RateLimitConfig::default()),
                ..ServerConfig::default()
            };

            let server = Server::new_network_frost_with_proxy(
                network_signer,
                transport_secret,
                &relays,
                Some(Arc::new(CallbackBridge { callbacks }) as Arc<dyn ServerCallbacks>),
                config,
                proxy,
            )
            .await
            .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            *self.bunker_url.lock().unwrap_or_else(|e| e.into_inner()) = Some(server.bunker_url());

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            *self.shutdown_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(shutdown_tx);

            let status = Arc::clone(&self.status);
            tokio::spawn(async move {
                status.store(STATUS_RUNNING, Ordering::Release);
                run_server(server, shutdown_rx, status).await;
            });

            Ok::<(), KeepMobileError>(())
        });

        if result.is_err() {
            self.set_status(STATUS_STOPPED);
        }
        result
    }
}

async fn run_server(
    mut server: Server,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    status: Arc<AtomicU8>,
) {
    tokio::select! {
        result = server.run() => {
            match result {
                Ok(()) => status.store(STATUS_STOPPED, Ordering::Release),
                Err(_) => status.store(STATUS_ERROR, Ordering::Release),
            };
        }
        _ = shutdown_rx => {
            server.stop().await;
            status.store(STATUS_STOPPED, Ordering::Release);
        }
    }
}
