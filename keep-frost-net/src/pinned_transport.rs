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
//! [`ConnectionMode::Direct`] and [`ConnectionMode::Proxy`] are both pinned
//! here. For a SOCKS5 proxy this transport opens the proxied stream itself and
//! runs the same pinned handshake over it, handing the relay hostname to the
//! proxy unresolved so no DNS lookup leaves the proxy. A SOCKS failure is an
//! error, never a fallback to a direct dial or to CA-only validation.
//!
//! The embedded Tor mode, which exists only when the relay stack is built with
//! its `tor` feature, builds its stream inside the relay stack's own websocket
//! crate and cannot be pinned here. Under [`TlsPinning::require_pinned`] it is
//! refused outright. Without it, it falls back to the default (unpinned)
//! transport, a real downgrade to CA-only validation on the data socket even
//! when a pin for that host is on record, so the fallback is logged rather than
//! taken quietly (once per host: the pool reconnects on a timer).

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
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
    RelayOptions, RelayStatus, Url,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{client_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream};

use keep_core::relay::{is_internal_ip, ALLOW_INTERNAL_HOSTS};

use crate::cert_pin::CertificatePinSet;
use crate::error::{FrostNetError, Result};
use crate::pinning::{PinFailureHook, PinningServerCertVerifier};

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
    on_failure: Option<PinFailureHook>,
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
            on_failure: None,
        }
    }

    /// Report a pin rejection on the handshake that carries relay data.
    ///
    /// The hook runs on the handshake thread. It must not block or call back
    /// into this transport. A reconnect reports a host once, until a later
    /// handshake for that host succeeds.
    pub fn on_pin_failure(mut self, hook: PinFailureHook) -> Self {
        self.on_failure = Some(hook);
        self
    }

    /// Whether a host with no pin on record is refused.
    pub fn require_pinned(&self) -> bool {
        self.require_pinned
    }

    /// The pin set handshakes are checked against. A pin added to it holds
    /// for every later handshake through a transport built from this.
    pub fn pins(&self) -> Arc<Mutex<CertificatePinSet>> {
        Arc::clone(&self.pins)
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

/// Stamp `proxy` onto per-relay options so a pool-added relay honors it.
///
/// `ClientOptions::connection`, which [`build_client`] sets, is read only by
/// `Client::add_relay`; `RelayPool::add_relay` takes the `RelayOptions` it is
/// given verbatim and the relay connects with that per-relay mode. Callers that
/// need their own relay options therefore go through the pool and have to carry
/// the mode themselves, or the proxy is silently dropped and the socket is
/// direct.
///
/// `keep-agent` keeps its own copy of this in `relay_opts`; it does not depend
/// on this crate, so the two have to be kept in step by hand.
pub fn with_proxy(opts: RelayOptions, proxy: Option<SocketAddr>) -> RelayOptions {
    match proxy {
        Some(addr) => opts.connection_mode(ConnectionMode::Proxy(addr)),
        None => opts,
    }
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
    /// Hosts already logged as un-pinnable (embedded Tor). The pool retries on a
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
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(pinning, roots)
    }

    fn with_roots(pinning: TlsPinning, roots: RootCertStore) -> Result<Self> {
        let require_pinned = pinning.require_pinned;

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

        let mut verifier = PinningServerCertVerifier::new_with_provider(
            Arc::new(roots),
            pinning.pins,
            require_pinned,
            provider.clone(),
        )
        .map_err(|e| {
            FrostNetError::Transport(format!("Failed to build pinning certificate verifier: {e}"))
        })?;
        if let Some(hook) = pinning.on_failure {
            verifier = verifier.with_on_pin_failure(hook);
        }

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

    /// Open a pinned connection: a TCP stream dialed direct or through the
    /// SOCKS5 `proxy`, then our pinning `ClientConfig` handed to the websocket
    /// TLS handshake over it. Every failure, a SOCKS one included, is an error
    /// and never a fallback to another transport or to a direct dial.
    async fn connect_pinned(
        &self,
        url: &Url,
        proxy: Option<SocketAddr>,
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

        // A cleartext relay has no certificate to pin, and strict mode already
        // refused it above; screening it too would reject the local relays a
        // `ws://` client dialed before pinning.
        let screen_internal = !ALLOW_INTERNAL_HOSTS && url.scheme() == "wss";

        let connect = async {
            let tcp = match proxy {
                Some(socks) => socks_dial(socks, &host, port, screen_internal).await?,
                None => direct_connect(&host, port, screen_internal).await?,
            };

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

/// Resolve `host` locally, screen the resolved addresses and dial one.
///
/// The screen matches the probe's guard. DNS resolution happens here, after any
/// URL-level check, so this is what actually stops a rebind onto a loopback or
/// link-local address.
async fn direct_connect(host: &str, port: u16, screen_internal: bool) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| FrostNetError::Transport(format!("DNS resolve {host}:{port}: {e}")))?
        .filter(|a| !screen_internal || !is_internal_ip(&a.ip()))
        .collect();
    if addrs.is_empty() {
        return Err(FrostNetError::Transport(format!(
            "Relay {host} has no connectable addresses"
        )));
    }
    happy_eyeballs_connect(&addrs)
        .await
        .map_err(|e| FrostNetError::Transport(format!("TCP connect to {host}:{port}: {e}")))
}

/// Open a SOCKS5 stream to `host` through `socks`.
///
/// A hostname is handed to the proxy unresolved: a local lookup would leak the
/// relay being contacted outside the proxy, which is what routing through it is
/// meant to prevent. With no address resolved on this side there is nothing to
/// screen, and a local lookup would not even be what the proxy resolves, so the
/// target is whatever the proxy reaches. An IP literal needs no lookup, so with
/// `screen_internal` it is screened as a direct dial would screen it.
///
/// Shared by the live socket and the pin probe, so both send a host the same
/// way. `host` is as `url::host_str` gives it, IPv6 literals bracketed.
pub(crate) async fn socks_dial(
    socks: SocketAddr,
    host: &str,
    port: u16,
    screen_internal: bool,
) -> Result<TcpStream> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if screen_internal && bare.parse::<IpAddr>().is_ok_and(|ip| is_internal_ip(&ip)) {
        return Err(FrostNetError::Transport(format!(
            "Relay {host} is an internal address"
        )));
    }
    Socks5Stream::connect(socks, (bare, port))
        .await
        .map(Socks5Stream::into_inner)
        .map_err(|e| {
            FrostNetError::Transport(format!("SOCKS connect to {host}:{port} via {socks}: {e}"))
        })
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
    /// Log an un-pinnable (embedded Tor) connection once per host. The pool
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
                "strict pinning REFUSES this relay: an embedded Tor connection cannot be \
                 pinned. Use a SOCKS proxy or disable strict pinning to connect."
            );
        } else {
            tracing::warn!(
                relay = %url,
                "certificate pin NOT enforced on this connection: the embedded Tor transport \
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
                ConnectionMode::Direct => self.connect_pinned(url, None, timeout).await,
                ConnectionMode::Proxy(socks) => {
                    self.connect_pinned(url, Some(*socks), timeout).await
                }
                // Only the embedded Tor mode is left, and only when the relay
                // stack is built with its `tor` feature, which nothing here
                // enables. Its stream is built inside the relay stack's
                // websocket crate, so the pin cannot be enforced on it. Fail
                // closed under strict pinning instead of quietly dropping to
                // CA-only validation.
                #[allow(unreachable_patterns)]
                _ => {
                    if self.require_pinned {
                        // Logged as well as refused: the caller surfaces only a
                        // generic "timed out waiting for relay", so without this
                        // the cause is invisible.
                        self.log_once_unpinnable(url, true);
                        return Err(TransportError::backend(FrostNetError::Transport(
                            "strict pinning: refusing a Tor relay connection, which this \
                             transport cannot pin"
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
    async fn with_proxy_reaches_a_pool_added_relay() {
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let client = build_client(&Keys::generate(), Some(proxy), None).unwrap();
        client
            .pool()
            .add_relay(
                "wss://relay.example.com",
                with_proxy(RelayOptions::default(), Some(proxy)),
            )
            .await
            .unwrap();
        let relay = client.relay("wss://relay.example.com").await.unwrap();
        assert_eq!(*relay.connection_mode(), ConnectionMode::Proxy(proxy));
    }

    #[tokio::test]
    async fn without_a_proxy_a_pool_added_relay_stays_direct() {
        let client = build_client(&Keys::generate(), None, None).unwrap();
        client
            .pool()
            .add_relay(
                "wss://relay.example.com",
                with_proxy(RelayOptions::default(), None),
            )
            .await
            .unwrap();
        let relay = client.relay("wss://relay.example.com").await.unwrap();
        assert_eq!(*relay.connection_mode(), ConnectionMode::Direct);
    }

    use async_wsocket::futures_util::SinkExt;
    use base64::Engine;
    use rustls::ServerConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::cert_pin::{extract_spki_from_der, hash_spki, SpkiHash};
    use crate::pinning::PinRejection;

    // A throwaway test CA and a leaf it signed for `relay.test`, valid until
    // 2126, with the leaf's PKCS#8 key. The pinned verifier still runs full
    // WebPKI validation, so the fixture relay needs a real chain to a root the
    // test transport trusts.
    const TEST_CA_DER_B64: &str = "MIIBlTCCATugAwIBAgIURP9ryDua2uS0nIkQimXGmw9LlNUwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMa2VlcC10ZXN0LWNhMCAXDTI2MTEyNjE3MDcxM1oYDzIxMjYxMTAyMTcwNzEzWjAXMRUwEwYDVQQDDAxrZWVwLXRlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASXnsAbj4xcAqBzaezjgTUm0EmCgoTtJk/p/0auq6GylOV6gUaosrfCPXir8EM1v5HvY7bP7SDtKnvLvY6aJKLGo2MwYTAdBgNVHQ4EFgQUuhwctlkXf9isUcJgFPNb94qcjOEwHwYDVR0jBBgwFoAUuhwctlkXf9isUcJgFPNb94qcjOEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhALKb52eXcjzGP64zk0jck0IAw7ZCu2Ryy0FeijP9MjcPAiBiF1GioU9rjXjrIvQU4d+tn8wEVuiQ4MtCcB2PSioGAQ==";
    const TEST_LEAF_DER_B64: &str = "MIIBvjCCAWSgAwIBAgIUDZBVlwdZ16Bkrmb42CrKBAxddlswCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMa2VlcC10ZXN0LWNhMCAXDTI2MTEyNjE3MDcxM1oYDzIxMjYxMTAyMTcwNzEzWjAVMRMwEQYDVQQDDApyZWxheS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEogNWSIskGYV2SYVboC+o9eAKzkEOcdVFS2EpTglwO9Wp3X3UPsO4WrqpNak18V/MamH6IMx2qWnK5mhL/ztxhqOBjTCBijAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAVBgNVHREEDjAMggpyZWxheS50ZXN0MB0GA1UdDgQWBBRonVUu6PjBexNQ8ZofrK6c/XvfIzAfBgNVHSMEGDAWgBS6HBy2WRd/2KxRwmAU81v3ipyM4TAKBggqhkjOPQQDAgNIADBFAiBdAlXAJtutNb61Lztrqx2vxgATXKmIPa4Hr06CdkWV/QIhAKvINdhKVxynvu8kijItqTZpHhalb3JQXM4S/CaIrEzy";
    const TEST_LEAF_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4K7P0++gBr/obfABddi7CAMGkcm7LHQJsQTS4nHnntGhRANCAASiA1ZIiyQZhXZJhVugL6j14ArOQQ5x1UVLYSlOCXA71andfdQ+w7hauqk1qTXxX8xqYfogzHapacrmaEv/O3GG";
    // openssl's SHA-256 over the leaf's DER SubjectPublicKeyInfo.
    const TEST_LEAF_PIN_HEX: &str =
        "92a3a9022d00f7707fa290aa2661d0464cb23e44ac8ab7541635827b1c1e6ff5";
    // Never resolvable locally, so a connect that works proves the name went
    // to the proxy rather than to a local lookup.
    const TEST_HOST: &str = "relay.test";
    const TEST_URL: &str = "wss://relay.test:4443";

    fn der(b64: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    fn leaf_pin() -> SpkiHash {
        let pin = hash_spki(&extract_spki_from_der(&der(TEST_LEAF_DER_B64)).unwrap());
        assert_eq!(hex::encode(pin), TEST_LEAF_PIN_HEX);
        pin
    }

    type Rejections = Arc<Mutex<Vec<(String, PinRejection)>>>;

    /// A transport that trusts only the test CA, with `pin` (if any) on record
    /// for the fixture host and every pin rejection recorded.
    fn fixture_transport(
        pin: Option<SpkiHash>,
        strict: bool,
    ) -> (PinnedWebSocketTransport, Rejections) {
        let pins = pin_set();
        if let Some(pin) = pin {
            pins.lock().unwrap().add_pin(TEST_HOST.into(), pin);
        }
        let rejections: Rejections = Arc::default();
        let seen = rejections.clone();
        let pinning = TlsPinning::new(pins, strict).on_pin_failure(Arc::new(move |host, why| {
            seen.lock().unwrap().push((host.to_string(), why));
        }));
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(der(TEST_CA_DER_B64)))
            .unwrap();
        (
            PinnedWebSocketTransport::with_roots(pinning, roots).unwrap(),
            rejections,
        )
    }

    /// A websocket relay over TLS with the test leaf, echoing every message.
    async fn spawn_tls_relay() -> SocketAddr {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der(TEST_LEAF_DER_B64))],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der(TEST_LEAF_KEY_B64))),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_text() && ws.send(msg).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A plain (`ws://`) websocket relay echoing every text message, as a relay
    /// behind an onion address is reached.
    async fn spawn_plain_relay() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_text() && ws.send(msg).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A minimal no-auth SOCKS5 proxy that sends every CONNECT to `upstream`
    /// and records the target it was asked for: `host:port` for a name, and
    /// `ip <addr>` for an address.
    async fn spawn_socks5(upstream: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let targets: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = targets.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    client.read_exact(&mut head).await.unwrap();
                    let mut methods = vec![0u8; head[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    client.write_all(&[5, 0]).await.unwrap();

                    let mut req = [0u8; 4];
                    client.read_exact(&mut req).await.unwrap();
                    assert_eq!(&req[..3], &[5, 1, 0], "only CONNECT is expected");
                    let target = match req[3] {
                        3 => {
                            let len = client.read_u8().await.unwrap();
                            let mut name = vec![0u8; len as usize];
                            client.read_exact(&mut name).await.unwrap();
                            let port = client.read_u16().await.unwrap();
                            format!("{}:{port}", String::from_utf8(name).unwrap())
                        }
                        1 => {
                            let mut ip = [0u8; 4];
                            client.read_exact(&mut ip).await.unwrap();
                            let port = client.read_u16().await.unwrap();
                            format!("ip {}", SocketAddr::from((ip, port)))
                        }
                        4 => {
                            let mut ip = [0u8; 16];
                            client.read_exact(&mut ip).await.unwrap();
                            let port = client.read_u16().await.unwrap();
                            format!("ip {}", SocketAddr::from((ip, port)))
                        }
                        other => panic!("unexpected SOCKS address type {other}"),
                    };
                    seen.lock().unwrap().push(target);

                    let mut relay = TcpStream::connect(upstream).await.unwrap();
                    client
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
                });
            }
        });
        (addr, targets)
    }

    /// The fixture relay behind the fixture proxy, as a `Proxy` mode.
    async fn proxied_relay() -> (ConnectionMode, Arc<Mutex<Vec<String>>>) {
        let relay = spawn_tls_relay().await;
        let (socks, targets) = spawn_socks5(relay).await;
        (ConnectionMode::Proxy(socks), targets)
    }

    /// Connect, then prove the socket carries data with one echoed message.
    async fn connect_and_echo(
        transport: &PinnedWebSocketTransport,
        url: &str,
        mode: &ConnectionMode,
    ) {
        let url = Url::parse(url).unwrap();
        let (mut sink, mut stream) =
            match transport.connect(&url, mode, Duration::from_secs(10)).await {
                Ok(pair) => pair,
                Err(e) => panic!("the proxied relay with a matching pin was refused: {e}"),
            };
        sink.send(Message::Text("ping".into())).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("no echo over the pinned proxied socket")
            .expect("the socket closed")
            .unwrap();
        assert!(matches!(echoed, Message::Text(ref t) if t == "ping"));
    }

    #[tokio::test]
    async fn a_proxied_relay_whose_pin_matches_connects() {
        let (mode, targets) = proxied_relay().await;
        let (t, rejections) = fixture_transport(Some(leaf_pin()), false);
        connect_and_echo(&t, TEST_URL, &mode).await;
        assert_eq!(*targets.lock().unwrap(), ["relay.test:4443"]);
        assert!(rejections.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn strict_mode_connects_a_proxied_relay_whose_pin_matches() {
        let (mode, targets) = proxied_relay().await;
        let (t, rejections) = fixture_transport(Some(leaf_pin()), true);
        connect_and_echo(&t, TEST_URL, &mode).await;
        assert_eq!(*targets.lock().unwrap(), ["relay.test:4443"]);
        assert!(rejections.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_proxied_relay_whose_pin_does_not_match_is_refused_in_both_modes() {
        for strict in [false, true] {
            let (mode, targets) = proxied_relay().await;
            let (t, rejections) = fixture_transport(Some([0x42; 32]), strict);
            let err = connect_err(
                &t,
                TEST_URL,
                &mode,
                "a proxied relay whose certificate does not match its pin was accepted",
            )
            .await;
            assert!(err.contains("Pinned TLS handshake"), "{err}");
            assert_eq!(*targets.lock().unwrap(), ["relay.test:4443"]);
            assert_eq!(
                *rejections.lock().unwrap(),
                [(TEST_HOST.to_string(), PinRejection::Mismatch)],
                "strict={strict}"
            );
        }
    }

    #[tokio::test]
    async fn strict_mode_refuses_a_proxied_relay_with_no_pin() {
        let (mode, _) = proxied_relay().await;
        let (t, rejections) = fixture_transport(None, true);
        let err = connect_err(
            &t,
            TEST_URL,
            &mode,
            "strict pinning accepted a proxied relay with no pin on record",
        )
        .await;
        assert!(err.contains("Pinned TLS handshake"), "{err}");
        assert_eq!(
            *rejections.lock().unwrap(),
            [(TEST_HOST.to_string(), PinRejection::Missing)]
        );
    }

    #[tokio::test]
    async fn a_dead_proxy_is_an_error_not_a_direct_dial() {
        // Nothing listens on port 1. A fallback to a direct dial would fail on
        // the local lookup of the unresolvable host instead.
        let (t, _) = fixture_transport(Some(leaf_pin()), false);
        let mode = ConnectionMode::Proxy("127.0.0.1:1".parse().unwrap());
        let err = connect_err(&t, TEST_URL, &mode, "the proxy is dead").await;
        assert!(err.contains("SOCKS connect"), "{err}");
    }

    async fn plain_proxied_relay() -> (ConnectionMode, Arc<Mutex<Vec<String>>>) {
        let relay = spawn_plain_relay().await;
        let (socks, targets) = spawn_socks5(relay).await;
        (ConnectionMode::Proxy(socks), targets)
    }

    #[tokio::test]
    async fn a_plain_relay_name_echoes_through_the_proxy() {
        let (mode, targets) = plain_proxied_relay().await;
        let (t, _) = fixture_transport(None, false);
        connect_and_echo(&t, "ws://relay.test:4443", &mode).await;
        assert_eq!(*targets.lock().unwrap(), ["relay.test:4443"]);
    }

    #[tokio::test]
    async fn ip_literals_reach_the_live_proxy_as_ip_targets() {
        let (mode, targets) = plain_proxied_relay().await;
        let (t, _) = fixture_transport(None, false);
        connect_and_echo(&t, "ws://127.0.0.1:4443", &mode).await;
        connect_and_echo(&t, "ws://[::1]:4443", &mode).await;
        assert_eq!(
            *targets.lock().unwrap(),
            ["ip 127.0.0.1:4443", "ip [::1]:4443"]
        );
    }

    #[tokio::test]
    async fn the_probe_sends_ip_literals_to_the_proxy_as_ip_targets() {
        let (mode, targets) = proxied_relay().await;
        let ConnectionMode::Proxy(socks) = mode else {
            unreachable!()
        };
        pin_set();
        let pins = CertificatePinSet::new();
        for relay in ["wss://1.1.1.1:4443", "wss://[2606:4700::1111]:4443"] {
            // The fixture's certificate is not for these names, so the probe
            // fails after the dial; only the target the proxy saw matters.
            let _ = crate::verify_relay_certificate(relay, &pins, false, Some(socks)).await;
        }
        assert_eq!(
            *targets.lock().unwrap(),
            ["ip 1.1.1.1:4443", "ip [2606:4700::1111]:4443"]
        );
    }

    #[tokio::test]
    async fn an_internal_ip_literal_is_refused_before_the_proxy_is_asked() {
        let (mode, targets) = proxied_relay().await;
        let ConnectionMode::Proxy(socks) = mode else {
            unreachable!()
        };
        for host in ["10.0.0.1", "[fd00::1]"] {
            let err = socks_dial(socks, host, 443, true).await.unwrap_err();
            assert!(err.to_string().contains("internal address"), "{err}");
        }
        pin_set();
        let err = crate::verify_relay_certificate(
            "wss://10.0.0.1",
            &CertificatePinSet::new(),
            false,
            Some(socks),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("internal address"), "{err}");
        assert!(targets.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_proxy_that_stalls_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((client, _)) = listener.accept().await {
                held.push(client);
            }
        });
        let (t, _) = fixture_transport(Some(leaf_pin()), false);
        let url = Url::parse(TEST_URL).unwrap();
        let started = std::time::Instant::now();
        let result = t
            .connect(
                &url,
                &ConnectionMode::Proxy(socks),
                Duration::from_millis(300),
            )
            .await;
        let err = match result {
            Ok(_) => panic!("a proxy that never answers let a connection through"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("Timeout:"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn an_overlong_host_is_refused_not_sent() {
        let (mode, targets) = plain_proxied_relay().await;
        let (t, _) = fixture_transport(None, false);
        let host = format!("{}test", format!("{}.", "a".repeat(60)).repeat(5));
        assert!(host.len() > 255);
        let err = connect_err(
            &t,
            &format!("ws://{host}:4443"),
            &mode,
            "a host too long for SOCKS5 was sent",
        )
        .await;
        assert!(err.contains("overlong"), "{err}");
        assert!(targets.lock().unwrap().is_empty());
    }
}
