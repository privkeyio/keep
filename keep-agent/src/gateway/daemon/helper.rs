// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep gateway relay`: the relay helper.
//!
//! The gateway keeps no network, so this helper, running as its own user
//! with network access and nothing else (no vault, no credential, no key),
//! talks to the relays for it. It connects to the gateway's relay socket,
//! checked to be the gateway's (see
//! [`super::server::connect_verified`]), and passes finished gift wraps both
//! ways: what the gateway publishes, and what the relays deliver for the
//! subscription the gateway asks for. It never sees inside a wrap, so a
//! compromised helper is no more than a hostile relay.

use std::path::Path;
use std::time::Duration;

use nostr_sdk::prelude::{
    Client, Event, Filter, JsonUtil, Kind, RelayOptions, RelayPoolNotification,
};
use serde_json::{json, Value};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::relay::MAX_RELAY_LINE;
use super::server::{connect_verified, write_line, LineReader, CONNECT_TIMEOUT};
use crate::error::{AgentError, Result};

/// The longest wait between attempts to reach the gateway.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How long a message no relay takes is tried again. Past the approval
/// deadline it would be refused anyway, but a freeze's anchor or an outcome
/// still counts later.
const PUBLISH_RETRY_FOR: Duration = Duration::from_secs(600);

/// How long writing a line to the gateway may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The relay options keep-frost-net's nodes use: reconnect with a ping so a
/// dropped link recovers, a relay that changes what it says it is dropped,
/// and a bounded average latency.
fn relay_opts() -> RelayOptions {
    RelayOptions::default()
        .reconnect(true)
        .ping(true)
        .retry_interval(Duration::from_secs(10))
        .adjust_retry_interval(true)
        .ban_relay_on_mismatch(true)
        .max_avg_latency(Some(Duration::from_secs(3)))
}

/// Run the helper for the gateway listening on `socket` as `gateway_uid`
/// until `shutdown` resolves, reconnecting whenever the gateway goes away.
pub async fn run_helper(
    socket: &Path,
    gateway_uid: u32,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    if super::euid() == 0 {
        return Err(AgentError::Other(
            "run the relay helper as its own user, never root".into(),
        ));
    }
    helper_loop(socket, gateway_uid, shutdown).await
}

/// [`run_helper`] without the check of its own user, for tests run as root.
pub(crate) async fn helper_loop(
    socket: &Path,
    gateway_uid: u32,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(shutdown);
    let mut backoff = Duration::from_secs(1);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            served = session(socket, gateway_uid) => {
                match served {
                    Ok(()) => {
                        tracing::warn!("the gateway closed the relay connection");
                        backoff = Duration::from_secs(1);
                    }
                    Err(e) => tracing::warn!(error = %e, "no relay connection to the gateway"),
                }
            }
        }
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// One connection to the gateway, with its own relay client.
async fn session(socket: &Path, gateway_uid: u32) -> Result<()> {
    let path = socket.to_path_buf();
    let stream =
        tokio::task::spawn_blocking(move || connect_verified(&path, gateway_uid, CONNECT_TIMEOUT))
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?
            .map_err(|e| AgentError::Other(e.to_string()))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| AgentError::Other(e.to_string()))?;
    let stream = UnixStream::from_std(stream).map_err(|e| AgentError::Other(e.to_string()))?;
    tracing::info!("connected to the gateway's relay socket");
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, MAX_RELAY_LINE);
    let (lines, mut queue) = mpsc::channel::<Value>(256);
    let writer = tokio::spawn(async move {
        while let Some(value) = queue.recv().await {
            if !write_line(&mut write, value.to_string().as_bytes(), WRITE_TIMEOUT).await {
                return;
            }
        }
    });
    let client = Client::default();
    let mut notifications = client.notifications();
    let result = loop {
        tokio::select! {
            line = reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if let Err(e) = from_gateway(&client, &line, &lines).await {
                            break Err(e);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(AgentError::Other(e.to_string())),
                }
            }
            notification = notifications.recv() => {
                match notification {
                    Ok(RelayPoolNotification::Event { event, .. }) if event.kind == Kind::GiftWrap => {
                        if lines.send(json!({ "event": *event })).await.is_err() {
                            break Ok(());
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "relay events were missed; they arrive again on the next subscription");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break Ok(()),
                }
            }
        }
    };
    client.shutdown().await;
    drop(lines);
    let _ = writer.await;
    result
}

/// Handle one line from the gateway.
async fn from_gateway(client: &Client, line: &[u8], lines: &mpsc::Sender<Value>) -> Result<()> {
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| AgentError::Other("the gateway sent a line that is not JSON".into()))?;
    if let Some(relays) = value.get("relays").and_then(Value::as_array) {
        for relay in relays.iter().filter_map(Value::as_str) {
            keep_approval::pairing::check_relay(relay)
                .map_err(|e| AgentError::Other(format!("relay {relay:?}: {e}")))?;
            client
                .pool()
                .add_relay(relay, relay_opts())
                .await
                .map_err(|e| AgentError::Other(format!("relay {relay:?}: {e}")))?;
        }
        client.connect().await;
        // Messages go out once a relay is there to take them; a relay that
        // never comes is retried in the background all the same.
        client.wait_for_connection(Duration::from_secs(10)).await;
        return Ok(());
    }
    if let Some(filter) = value.get("subscribe") {
        let filter = Filter::from_json(filter.to_string())
            .map_err(|e| AgentError::Other(format!("subscription: {e}")))?;
        client
            .subscribe(filter, None)
            .await
            .map_err(|e| AgentError::Other(format!("subscribe: {e}")))?;
        return Ok(());
    }
    if let Some(event) = value.get("publish") {
        let event = Event::from_json(event.to_string())
            .map_err(|e| AgentError::Other(format!("publish: {e}")))?;
        if event.kind != Kind::GiftWrap {
            return Err(AgentError::Other(
                "the gateway asked to publish something other than a gift wrap".into(),
            ));
        }
        // Sent apart, so a slow relay holds up nothing else, and tried again
        // while no relay takes it, as long as a receiver could still accept
        // it.
        let (client, lines) = (client.clone(), lines.clone());
        tokio::spawn(async move {
            let id = event.id.to_hex();
            let mut wait = Duration::from_secs(1);
            let give_up = tokio::time::Instant::now() + PUBLISH_RETRY_FOR;
            let ok = loop {
                match client.send_event(&event).await {
                    Ok(output) if !output.success.is_empty() => break true,
                    Ok(_) => tracing::warn!(%id, "no relay took an approval message yet"),
                    Err(e) => {
                        tracing::warn!(%id, error = %e, "an approval message was not published yet")
                    }
                }
                if tokio::time::Instant::now() + wait > give_up {
                    break false;
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(MAX_BACKOFF);
            };
            let _ = lines.send(json!({ "published": id, "ok": ok })).await;
        });
        return Ok(());
    }
    tracing::warn!("the gateway sent a line the helper does not know");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper publishes gift wraps only: anything else the gateway asks
    /// it to publish ends the connection, sent nowhere.
    #[tokio::test]
    async fn the_helper_publishes_nothing_but_gift_wraps() {
        let client = Client::default();
        let (lines, _queue) = mpsc::channel(4);
        let keys = nostr_sdk::prelude::Keys::generate();
        let note = nostr_sdk::prelude::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let line = json!({ "publish": note }).to_string();
        let refused = from_gateway(&client, line.as_bytes(), &lines).await;
        assert!(refused
            .unwrap_err()
            .to_string()
            .contains("other than a gift wrap"),);
    }
}
