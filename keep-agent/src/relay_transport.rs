// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Relay transport that never dials an internal address.
//
// Relay URLs reach the agent from bunker URIs and from a signer's
// switch_relays answer. validate_relay_url only judges the host as written, so
// a public-looking name that resolves to loopback, a LAN or a cloud metadata
// address would pass, and nostr-sdk's default transport dials whatever DNS
// returns. This resolves once, drops internal addresses, and connects only to
// what is left, so there is no second lookup to rebind. The handshake is the
// one the default transport runs on its own socket.
//
// keep-frost-net's pinned transport does the same screening, but depending on
// it would bring its TLS backend and enclave host into the agent SDK.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::futures_util::stream::SplitSink;
use async_wsocket::futures_util::{Sink, StreamExt, TryStreamExt};
use async_wsocket::{Message, WebSocket};
use keep_core::relay::{is_internal_ip, ALLOW_INTERNAL_HOSTS};
use nostr_sdk::prelude::transport::error::TransportError;
use nostr_sdk::prelude::transport::websocket::{
    DefaultWebsocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport,
};
use nostr_sdk::prelude::{BoxedFuture, ConnectionMode, Url};
use tokio::net::TcpStream;

use crate::error::AgentError;

#[derive(Debug)]
pub(crate) struct ScreenedTransport {
    allow_internal: bool,
}

impl Default for ScreenedTransport {
    fn default() -> Self {
        Self {
            allow_internal: ALLOW_INTERNAL_HOSTS,
        }
    }
}

impl WebSocketTransport for ScreenedTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        mode: &'a ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
        Box::pin(async move {
            match mode {
                ConnectionMode::Direct => connect_screened(url, timeout, self.allow_internal).await,
                // The proxy resolves the name, so this transport cannot
                // screen where it connects.
                _ => DefaultWebsocketTransport.connect(url, mode, timeout).await,
            }
        })
    }
}

fn refused(reason: String) -> TransportError {
    TransportError::backend(AgentError::Connection(reason))
}

async fn connect_screened(
    url: &Url,
    timeout: Duration,
    allow_internal: bool,
) -> Result<(WebSocketSink, WebSocketStream), TransportError> {
    let host = url
        .host_str()
        .ok_or_else(|| refused("relay URL has no host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| refused("relay URL has no port".into()))?;

    let connect = async {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| refused(format!("resolve {host}:{port}: {e}")))?
            .collect();
        let addrs = screen(addrs, allow_internal);
        if addrs.is_empty() {
            return Err(refused(format!(
                "relay {host} has no connectable public address"
            )));
        }
        let tcp = happy_eyeballs_connect(&addrs)
            .await
            .map_err(|e| refused(format!("connect to {host}:{port}: {e}")))?;
        let (stream, _) = Box::pin(tokio_tungstenite::client_async_tls(url.as_str(), tcp))
            .await
            .map_err(TransportError::backend)?;
        Ok(stream)
    };

    let stream = tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| refused(format!("connect to relay {host}:{port} timed out")))??;

    let (tx, rx) = WebSocket::Tokio(stream).split();
    let sink: WebSocketSink = Box::new(ScreenedSink(tx));
    let stream: WebSocketStream = Box::pin(rx.map_err(TransportError::backend));
    Ok((sink, stream))
}

fn screen(addrs: Vec<SocketAddr>, allow_internal: bool) -> Vec<SocketAddr> {
    if allow_internal {
        return addrs;
    }
    addrs
        .into_iter()
        .filter(|a| !is_internal_ip(&a.ip()))
        .collect()
}

const HAPPY_EYEBALLS_HEAD_START: Duration = Duration::from_millis(250);

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

// RFC 8305, as the default transport does, so a blackholed IPv6 route does not
// burn the whole connect timeout before IPv4 is tried.
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

// Mapped by hand rather than with `sink_map_err`, which the relay pool's own
// transport notes can panic.
struct ScreenedSink(SplitSink<WebSocket, Message>);

impl Sink<Message> for ScreenedSink {
    type Error = TransportError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(item)
            .map_err(TransportError::backend)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(TransportError::backend)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(TransportError::backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // The listener stands in for a service on loopback. Each URL reaches it
    // and must be refused before any TCP connection is opened.
    #[tokio::test]
    async fn a_relay_resolving_to_loopback_is_never_dialed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        for url in [
            format!("wss://127.0.0.1:{port}/"),
            format!("wss://localhost:{port}/"),
            format!("ws://127.0.0.1:{port}/"),
            format!("ws://localhost:{port}/"),
        ] {
            let url = Url::parse(&url).unwrap();
            // Set by hand, since a workspace test run turns the feature on.
            let transport = ScreenedTransport {
                allow_internal: false,
            };
            let result = transport
                .connect(&url, &ConnectionMode::Direct, Duration::from_secs(5))
                .await;
            match result {
                Ok(_) => panic!("{url} connected"),
                Err(e) => assert!(
                    e.to_string().contains("no connectable public address"),
                    "{e}"
                ),
            }
        }
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err(), "a loopback connection was opened");
    }

    // Only the public addresses of an answer that mixes them with internal
    // ones are kept, in order.
    #[test]
    fn a_mixed_answer_keeps_only_public_addresses() {
        let addrs: Vec<SocketAddr> = [
            "127.0.0.1:443",
            "8.8.8.8:443",
            "10.0.0.1:443",
            "169.254.169.254:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "[2001:4860:4860::8888]:443",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let kept: Vec<String> = screen(addrs.clone(), false)
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(kept, ["8.8.8.8:443", "[2001:4860:4860::8888]:443"]);
        assert_eq!(screen(addrs.clone(), true), addrs);
    }

    // The pool carries relay traffic over this transport: a local relay, let
    // through by the internal-address opt-in, takes a published event and
    // serves it back.
    #[tokio::test]
    async fn a_relay_client_round_trips_an_event_through_it() {
        use nostr_sdk::prelude::{EventBuilder, Filter, Keys, Kind};

        let mut relay = None;
        for _ in 0..8 {
            if let Ok(r) = nostr_relay_builder::MockRelay::run().await {
                relay = Some(r);
                break;
            }
        }
        let relay = relay.expect("mock relay start");
        let keys = Keys::generate();
        let client = nostr_sdk::Client::builder()
            .signer(keys.clone())
            .websocket_transport(ScreenedTransport {
                allow_internal: true,
            })
            .build();
        client.add_relay(relay.url().await).await.unwrap();
        client.connect().await;
        client.wait_for_connection(Duration::from_secs(5)).await;

        let sent = client
            .send_event_builder(EventBuilder::text_note("screened"))
            .await
            .unwrap();
        let filter = Filter::new().author(keys.public_key()).kind(Kind::TextNote);
        let events = client
            .fetch_events(filter, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(events.iter().any(|e| e.id == *sent.id()));
    }
}
