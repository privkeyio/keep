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
//! Only [`ConnectionMode::Direct`] can be pinned here: the proxy and Tor modes
//! build their streams inside the relay stack's own websocket crate, which this
//! transport does not drive. Under [`TlsPinning::require_pinned`] those modes
//! are refused outright. Without it they fall back to the default (unpinned)
//! transport, which is a real downgrade to CA-only validation on the data
//! socket even when a pin for that host is on record, so the fallback is logged
//! at warn rather than taken quietly. Pinning those modes needs the proxy and
//! Tor stream construction brought into this transport.

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
    BoxedFuture, Client, ClientOptions, Connection, ConnectionMode, ConnectionTarget, Keys, Url,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream};

use keep_core::relay::{is_internal_ip, ALLOW_INTERNAL_HOSTS};

use crate::cert_pin::CertificatePinSet;
use crate::error::{FrostNetError, Result};
use crate::pinning::{OnNewPin, PinningServerCertVerifier};

/// How the pin set, strict-mode flag and trust-on-first-use hook are handed to
/// the transport.
///
/// `pins` is shared (not copied) so a pin recorded on a live handshake is
/// visible to the owner once the connection is up. That is how callers persist
/// trust-on-first-use pins without doing storage I/O inside a TLS handshake:
/// connect, then read the set back and write it out if it grew. `on_new_pin` is
/// available for callers that would rather be notified, but it runs on the
/// handshake path and must stay cheap and non-blocking.
#[derive(Clone)]
pub struct TlsPinning {
    pins: Arc<Mutex<CertificatePinSet>>,
    require_pinned: bool,
    on_new_pin: Option<OnNewPin>,
}

impl fmt::Debug for TlsPinning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPinning")
            .field("require_pinned", &self.require_pinned)
            .field("has_on_new_pin", &self.on_new_pin.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsPinning {
    /// Pin against `pins`. With `require_pinned` set, a host with no
    /// pre-provisioned pin is refused instead of trusted on first use, which is
    /// what closes the first-connection window.
    pub fn new(pins: Arc<Mutex<CertificatePinSet>>, require_pinned: bool) -> Self {
        Self {
            pins,
            require_pinned,
            on_new_pin: None,
        }
    }

    /// Add a trust-on-first-use notification hook. Runs inside the handshake.
    pub fn with_on_new_pin(mut self, on_new_pin: OnNewPin) -> Self {
        self.on_new_pin = Some(on_new_pin);
        self
    }

    /// The shared pin set, for reading back pins recorded on a live handshake.
    pub fn pins(&self) -> &Arc<Mutex<CertificatePinSet>> {
        &self.pins
    }

    /// Whether an un-pinned host is refused rather than trusted on first use.
    pub fn require_pinned(&self) -> bool {
        self.require_pinned
    }
}

/// Build the relay client, installing the SPKI-pinning transport when
/// `pinning` is supplied.
///
/// `Client::new(signer)` is itself `Client::builder().signer(signer).build()`,
/// so the unpinned result here is identical to what the callers built before.
pub(crate) fn build_client(
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

/// A [`WebSocketTransport`] that enforces the SPKI pin on the handshake
/// carrying relay data. See the module docs for the mode coverage.
pub struct PinnedWebSocketTransport {
    config: Arc<ClientConfig>,
    require_pinned: bool,
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

        let verifier = PinningServerCertVerifier::new(
            Arc::new(roots),
            pinning.pins,
            require_pinned,
            pinning.on_new_pin,
        )
        .map_err(|e| {
            FrostNetError::Transport(format!("Failed to build pinning certificate verifier: {e}"))
        })?;

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(Self {
            config: Arc::new(config),
            require_pinned,
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

            let tcp = TcpStream::connect(&addrs[..]).await.map_err(|e| {
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
                        return Err(TransportError::backend(FrostNetError::Transport(
                            "strict pinning: refusing a proxied or Tor relay connection, which \
                             this transport cannot pin"
                                .into(),
                        )));
                    }
                    // Not a silent downgrade: this socket gets CA-only
                    // validation even if a pin for the host is on record, so it
                    // is recorded where an operator can see it.
                    tracing::warn!(
                        relay = %url,
                        "certificate pin NOT enforced on this connection: proxied or Tor \
                         transport cannot be pinned; falling back to CA-only validation"
                    );
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
