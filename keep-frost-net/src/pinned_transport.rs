// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! SPKI-pinned websocket transport for the live relay connection.
//!
//! nostr-sdk's default transport builds its relay sockets with standard WebPKI
//! CA validation only, so enforcing a pin on a separate pre-flight probe (what
//! [`verify_relay_certificate`](crate::verify_relay_certificate) does on its
//! own) is a TOCTOU: the probe and the data socket are two different
//! handshakes, and an on-path attacker can answer them differently. A
//! CA-valid-but-unpinned certificate (mis-issued CA, device-installed
//! corporate MitM root) is exactly what SPKI pinning is supposed to catch, and
//! the probe cannot catch it on the socket that carries share and signing
//! traffic.
//!
//! This transport closes that gap by construction: it installs
//! [`PinningServerCertVerifier`] into the `rustls::ClientConfig` of the socket
//! the relay data actually flows over, so the pin is checked inside that
//! handshake. It plugs in through nostr-sdk's public
//! [`WebSocketTransport`] seam, so no fork of the relay stack is needed.
//!
//! This path only ever *enforces* a pin; it never records one. Learning a pin on
//! first use stays with the pre-flight probe, which runs under the caller's pin
//! lock and is allowed to touch storage. Recording trust from inside a handshake
//! would let an on-path attacker holding any CA-valid certificate pin itself,
//! and would silently re-add a pin the user had just cleared.
//!
//! Only [`ConnectionMode::Direct`] can be pinned here: the proxy and Tor modes
//! build their streams inside the relay stack's own websocket crate, which this
//! transport does not drive. Under [`TlsPinning::require_pinned`] those modes
//! are refused outright. Without it they fall back to the default (unpinned)
//! transport, which is a real downgrade to CA-only validation on the data
//! socket even when a pin for that host is on record, so the fallback is logged
//! rather than taken quietly (once per host: the pool reconnects on a timer).
//! Pinning those modes needs the proxy and Tor stream construction brought into
//! this transport.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::futures_util::stream::SplitSink;
use async_wsocket::futures_util::{Sink, StreamExt, TryStreamExt};
use async_wsocket::{Message, WebSocket};
use nostr_sdk::prelude::transport::error::TransportError;
use nostr_sdk::prelude::transport::websocket::{
    DefaultWebsocketTransport, WebSocketSink, WebSocketStream as PoolWebSocketStream,
    WebSocketTransport,
};
use nostr_sdk::prelude::{
    BoxedFuture, Client, ClientOptions, Connection, ConnectionMode, ConnectionTarget, Keys,
    RelayStatus, Url,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream};

use keep_core::relay::{is_internal_ip, ALLOW_INTERNAL_HOSTS};

use crate::cert_pin::CertificatePinSet;
use crate::error::{FrostNetError, Result};
use crate::pinning::PinningServerCertVerifier;

/// How the pin set and the strict-mode flag are handed to the transport.
///
/// `pins` is shared rather than copied, and read-only on this path: the live
/// handshake enforces whatever is on record but never writes to it. Sharing
/// rather than snapshotting means a pin staged or cleared through the UI is
/// picked up by the next full handshake, including an automatic reconnect,
/// without tearing the node down. Nothing has to be written back afterwards, so
/// there is no window in which a connection can clobber a concurrent edit.
#[derive(Clone)]
pub struct TlsPinning {
    pins: Arc<Mutex<CertificatePinSet>>,
    require_pinned: bool,
}

impl fmt::Debug for TlsPinning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPinning")
            .field("require_pinned", &self.require_pinned)
            .finish_non_exhaustive()
    }
}

impl TlsPinning {
    /// Pin against `pins`. With `require_pinned` set, a host with no pin on
    /// record is refused rather than accepted on standard validation alone,
    /// which is what closes the first-connection window.
    pub fn new(pins: Arc<Mutex<CertificatePinSet>>, require_pinned: bool) -> Self {
        Self {
            pins,
            require_pinned,
        }
    }

    /// Whether a host with no pin on record is refused.
    pub fn require_pinned(&self) -> bool {
        self.require_pinned
    }
}

/// Build the relay client, installing the SPKI-pinning transport when
/// `pinning` is supplied.
///
/// `Client::new(signer)` is itself `Client::builder().signer(signer).build()`,
/// so the unpinned result here is identical to what the callers built before.
pub fn build_client(
    keys: &Keys,
    proxy: Option<SocketAddr>,
    pinning: Option<TlsPinning>,
) -> Result<Client> {
    let mut builder = Client::builder().signer(keys.clone());

    if let Some(addr) = proxy {
        let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
        builder = builder.opts(ClientOptions::new().connection(connection));
    }

    if let Some(pinning) = pinning {
        builder = builder.websocket_transport(PinnedWebSocketTransport::new(pinning)?);
    }

    Ok(builder.build())
}

/// Wait for at least one relay to reach `Connected`, or fail.
///
/// `Client::connect` only spawns background attempts and a `subscribe` queues
/// against an empty pool, so both return `Ok` while every socket is being
/// refused. A caller that installed [`PinnedWebSocketTransport`] has to know
/// the difference: a pin mismatch or a scheme the transport cannot pin refuses
/// every relay, and without this the caller reports success and then carries no
/// traffic at all.
pub async fn wait_for_any_relay(client: &Client, within: Duration) -> Result<()> {
    tokio::time::timeout(within, async {
        loop {
            let relays = client.relays().await;
            if relays
                .values()
                .any(|r| matches!(r.status(), RelayStatus::Connected))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| FrostNetError::Transport("Timed out waiting for relay connection".into()))
}

/// A [`WebSocketTransport`] that enforces the SPKI pin on the handshake
/// carrying relay data. See the module docs for the mode coverage.
pub struct PinnedWebSocketTransport {
    config: Arc<ClientConfig>,
    require_pinned: bool,
    /// Hosts already logged as un-pinnable (proxy/Tor). The pool retries on a
    /// timer, so this keeps one downgrade from filling the log for a session.
    warned_unpinnable: Mutex<HashSet<String>>,
}

impl fmt::Debug for PinnedWebSocketTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedWebSocketTransport")
            .field("require_pinned", &self.require_pinned)
            .finish_non_exhaustive()
    }
}

impl PinnedWebSocketTransport {
    /// Build the transport, wiring `pinning` into a `rustls::ClientConfig`
    /// layered on top of the WebPKI roots. Pinning only ever tightens trust:
    /// [`PinningServerCertVerifier`] runs standard validation first and
    /// enforces the pin on the leaf that already passed.
    pub fn new(pinning: TlsPinning) -> Result<Self> {
        let require_pinned = pinning.require_pinned;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Both `ClientConfig::builder()` and `WebPkiServerVerifier::builder()`
        // PANIC when no process-default crypto provider is installed, and the
        // default is not inferable here because both `ring` and `aws-lc-rs` end
        // up enabled on rustls through the relay stack. Resolve it explicitly
        // and hand it to BOTH builders: this is a library entry point reached
        // across the UniFFI boundary, where an abort would take the host app
        // down instead of returning an error. Resolving it before the verifier
        // is built is load-bearing, not cosmetic.
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

        let verifier = PinningServerCertVerifier::new_with_provider(
            Arc::new(roots),
            pinning.pins,
            require_pinned,
            provider.clone(),
        )
        .map_err(|e| {
            FrostNetError::Transport(format!("Failed to build pinning certificate verifier: {e}"))
        })?;

        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                FrostNetError::Transport(format!("Failed to configure TLS versions: {e}"))
            })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(Self {
            config: Arc::new(config),
            require_pinned,
            warned_unpinnable: Mutex::new(HashSet::new()),
        })
    }

    /// Open a pinned direct connection: resolve, screen the resolved addresses,
    /// TCP connect, then hand our pinning `ClientConfig` to the websocket TLS
    /// handshake.
    async fn connect_pinned(
        &self,
        url: &Url,
        timeout: Duration,
    ) -> std::result::Result<(WebSocketSink, PoolWebSocketStream), TransportError> {
        // Under strict pinning there is nothing to pin on a cleartext socket,
        // so refuse rather than carry data over an unauthenticated channel.
        if self.require_pinned && url.scheme() != "wss" {
            return Err(TransportError::backend(FrostNetError::Transport(format!(
                "strict pinning: refusing non-TLS relay scheme {}://",
                url.scheme()
            ))));
        }

        let host = url
            .host_str()
            .ok_or_else(|| {
                TransportError::backend(FrostNetError::Transport("Relay URL has no host".into()))
            })?
            .to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            TransportError::backend(FrostNetError::Transport(
                "Relay URL has no port and no known default".into(),
            ))
        })?;

        let connect = async {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| FrostNetError::Transport(format!("DNS resolve {host}:{port}: {e}")))?
                .collect();

            // Screen the addresses we are about to dial, matching the probe's
            // guard. DNS resolution happens here, after any URL-level check, so
            // this is what actually stops a rebind onto a loopback or
            // link-local address.
            let addrs: Vec<SocketAddr> = if ALLOW_INTERNAL_HOSTS {
                addrs
            } else {
                addrs
                    .into_iter()
                    .filter(|a| !is_internal_ip(&a.ip()))
                    .collect()
            };
            if addrs.is_empty() {
                return Err(FrostNetError::Transport(format!(
                    "Relay {host} has no connectable addresses"
                )));
            }

            let tcp = happy_eyeballs_connect(&addrs).await.map_err(|e| {
                FrostNetError::Transport(format!("TCP connect to {host}:{port}: {e}"))
            })?;

            let (stream, _response) = client_async_tls_with_config(
                url.as_str(),
                tcp,
                None,
                Some(Connector::Rustls(self.config.clone())),
            )
            .await
            .map_err(|e| {
                // A pin mismatch surfaces here as a rustls handshake failure;
                // the verifier has already rejected it, so the connection is
                // never used either way.
                FrostNetError::Transport(format!("Pinned TLS handshake with {host}: {e}"))
            })?;

            Ok::<_, FrostNetError>(stream)
        };

        let stream = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| {
                TransportError::backend(FrostNetError::Timeout(format!(
                    "connect to relay {host}:{port}"
                )))
            })?
            .map_err(TransportError::backend)?;

        Ok(split_stream(stream))
    }
}

/// Split a connected websocket into the sink/stream pair the relay pool wants.
///
/// The pinned stream is wrapped in the relay stack's own [`WebSocket`] so its
/// message conversion and error mapping are reused verbatim; only the TLS
/// config underneath differs from the default transport.
fn split_stream(
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> (WebSocketSink, PoolWebSocketStream) {
    let (tx, rx) = WebSocket::Tokio(stream).split();
    // Wrap the sink by hand rather than with `sink_map_err`, which the relay
    // pool's own transport notes can panic.
    let sink: WebSocketSink = Box::new(PinnedSink(tx)) as WebSocketSink;
    let stream: PoolWebSocketStream =
        Box::pin(rx.map_err(TransportError::backend)) as PoolWebSocketStream;
    (sink, stream)
}

/// Head start the first address family gets before the other is raced, per
/// RFC 8305.
const HAPPY_EYEBALLS_HEAD_START: Duration = Duration::from_millis(250);

/// Try each address in turn, returning the last error if none connect.
async fn connect_sequential(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no connectable addresses",
        )
    }))
}

/// Connect with RFC 8305 "happy eyeballs" racing: start on IPv6, and if it has
/// not answered within [`HAPPY_EYEBALLS_HEAD_START`], race IPv4 alongside it.
///
/// The default transport this replaces did the same (`async-wsocket`'s
/// `happy_eyeballs_connect`). Connecting strictly in sequence instead would let
/// a blackholed IPv6 route burn the full SYN timeout before IPv4 is tried,
/// which on the node's wait-for-any-relay budget turns a working dual-stack
/// network into a failed connect.
async fn happy_eyeballs_connect(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().copied().partition(|a| a.is_ipv6());
    if v6.is_empty() || v4.is_empty() {
        return connect_sequential(addrs).await;
    }

    let v6_attempt = connect_sequential(&v6);
    let v4_attempt = async {
        tokio::time::sleep(HAPPY_EYEBALLS_HEAD_START).await;
        connect_sequential(&v4).await
    };
    tokio::pin!(v6_attempt);
    tokio::pin!(v4_attempt);

    // Whichever family connects first wins; if one fails outright, fall back to
    // waiting on the other rather than failing the whole connect.
    tokio::select! {
        result = &mut v6_attempt => match result {
            Ok(stream) => Ok(stream),
            Err(_) => v4_attempt.await,
        },
        result = &mut v4_attempt => match result {
            Ok(stream) => Ok(stream),
            Err(_) => v6_attempt.await,
        },
    }
}

impl PinnedWebSocketTransport {
    /// Log an un-pinnable (proxied or Tor) connection once per host. The pool
    /// reconnects on a timer, so logging every attempt would repeat the line for
    /// the life of the process.
    fn log_once_unpinnable(&self, url: &Url, strict: bool) {
        let host = url.host_str().unwrap_or("unknown").to_string();
        let mut warned = self
            .warned_unpinnable
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !warned.insert(host) {
            return;
        }
        if strict {
            tracing::error!(
                relay = %url,
                "strict pinning REFUSES this relay: a proxied or Tor connection cannot be \
                 pinned. Disable the proxy or strict pinning to connect."
            );
        } else {
            tracing::warn!(
                relay = %url,
                "certificate pin NOT enforced on this connection: proxied or Tor transport \
                 cannot be pinned; falling back to CA-only validation"
            );
        }
    }
}

impl WebSocketTransport for PinnedWebSocketTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        mode: &'a ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, std::result::Result<(WebSocketSink, PoolWebSocketStream), TransportError>>
    {
        Box::pin(async move {
            match mode {
                ConnectionMode::Direct => self.connect_pinned(url, timeout).await,
                // Proxy and Tor streams are built inside the relay stack's
                // websocket crate, which this transport does not drive, so the
                // pin cannot be enforced on them here. Fail closed under strict
                // pinning instead of quietly dropping to CA-only validation.
                _ => {
                    if self.require_pinned {
                        // Logged as well as refused: every relay is affected
                        // when a proxy is configured, and the caller surfaces
                        // only a generic "timed out waiting for relay", so
                        // without this the cause is invisible.
                        self.log_once_unpinnable(url, true);
                        return Err(TransportError::backend(FrostNetError::Transport(
                            "strict pinning: refusing a proxied or Tor relay connection, which \
                             this transport cannot pin"
                                .into(),
                        )));
                    }
                    // Not a silent downgrade: this socket gets CA-only
                    // validation even if a pin for the host is on record, so it
                    // is recorded where an operator can see it.
                    self.log_once_unpinnable(url, false);
                    DefaultWebsocketTransport.connect(url, mode, timeout).await
                }
            }
        })
    }
}

/// Sink half, mapping the websocket error into the relay pool's error type.
struct PinnedSink(SplitSink<WebSocket, Message>);

impl Sink<Message> for PinnedSink {
    type Error = TransportError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(item)
            .map_err(TransportError::backend)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(TransportError::backend)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(TransportError::backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    static SETUP: Once = Once::new();

    /// Both `ring` and `aws-lc-rs` end up enabled on rustls through the relay
    /// stack, so the provider is never inferable and must be installed
    /// explicitly. Every binary does this at startup; tests must too.
    fn pin_set() -> Arc<Mutex<CertificatePinSet>> {
        SETUP.call_once(crate::install_default_crypto_provider);
        Arc::new(Mutex::new(CertificatePinSet::new()))
    }

    /// The success half of `connect` holds trait objects that are not `Debug`,
    /// so the error cannot be taken with `expect_err`.
    async fn connect_err(
        transport: &PinnedWebSocketTransport,
        url: &str,
        mode: &ConnectionMode,
        expectation: &str,
    ) -> String {
        let url = Url::parse(url).unwrap();
        match transport.connect(&url, mode, Duration::from_secs(5)).await {
            Ok(_) => panic!("{expectation}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn transport_builds_in_both_modes() {
        assert!(
            !PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), false))
                .unwrap()
                .require_pinned
        );
        assert!(
            PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), true))
                .unwrap()
                .require_pinned
        );
    }

    #[test]
    fn transport_supports_ping_like_the_default() {
        let t = PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), false)).unwrap();
        assert!(t.support_ping());
        assert_eq!(t.support_ping(), DefaultWebsocketTransport.support_ping());
    }

    #[tokio::test]
    async fn strict_mode_refuses_a_cleartext_relay() {
        let t = PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), true)).unwrap();
        let err = connect_err(
            &t,
            "ws://relay.example.com",
            &ConnectionMode::Direct,
            "a cleartext relay has no certificate to pin",
        )
        .await;
        assert!(err.contains("refusing non-TLS relay scheme"), "{err}");
    }

    #[tokio::test]
    async fn lenient_mode_allows_a_cleartext_relay_past_the_scheme_guard() {
        // Not pinnable, but not refused on scheme either: the failure must come
        // from the connection attempt, not the strict-mode guard.
        let t = PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), false)).unwrap();
        let err = connect_err(
            &t,
            "ws://127.0.0.1:1",
            &ConnectionMode::Direct,
            "nothing is listening on port 1",
        )
        .await;
        assert!(!err.contains("refusing non-TLS relay scheme"), "{err}");
    }

    #[tokio::test]
    async fn strict_mode_refuses_a_proxied_connection_it_cannot_pin() {
        let t = PinnedWebSocketTransport::new(TlsPinning::new(pin_set(), true)).unwrap();
        let proxy = ConnectionMode::proxy("127.0.0.1:9050".parse::<SocketAddr>().unwrap());
        let err = connect_err(
            &t,
            "wss://relay.example.com",
            &proxy,
            "a proxied stream cannot be pinned by this transport",
        )
        .await;
        assert!(err.contains("cannot pin"), "{err}");
    }
}
