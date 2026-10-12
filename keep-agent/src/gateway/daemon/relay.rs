// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The gateway's side of the relay helper's socket.
//!
//! The gateway has no network: a helper, `keep gateway relay`, runs as its
//! own user and talks to the relays for it. The gateway listens on a socket
//! only that user may use, accepts one helper at a time, and exchanges one
//! JSON object per line, at most [`MAX_RELAY_LINE`] bytes:
//!
//! - to the helper: `{"relays": [urls]}`, `{"subscribe": filter}` and
//!   `{"publish": event}`;
//! - from the helper: `{"event": event}` and `{"published": id, "ok": bool}`.
//!
//! The helper only ever handles finished gift wraps, so it sees no more than
//! a relay does; a helper that misbehaves is a hostile relay, which the
//! protocol already assumes.

use std::time::Duration;

use nostr_sdk::prelude::{Event, JsonUtil};
use serde_json::{json, Value};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::approvals::{lock, RelayLink};
use super::server::{with_state, write_line, LineReader, Shared};

/// The longest line on the relay socket.
pub const MAX_RELAY_LINE: usize = 128 * 1024;

/// How far back the subscription asks relays for wraps: the time window
/// wraps are accepted in.
const SINCE_SECS: u64 = keep_approval::wrap::WINDOW_PAST_SECS;

/// How long writing a line to the helper may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

fn wall() -> u64 {
    super::clock::wall_clock().unwrap_or(0)
}

/// Accept the relay helper, one connection at a time and only from
/// `relay_uid`, and serve it until the gateway stops.
pub(crate) async fn relay_task(
    listener: UnixListener,
    relay_uid: u32,
    mut link: RelayLink,
    state: Shared,
    stop: watch::Sender<bool>,
) {
    let mut unsent: Option<Event> = None;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "relay socket accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(_) => continue,
        };
        if uid != relay_uid {
            tracing::warn!(
                uid,
                "relay socket connection refused: not the relay helper's user"
            );
            continue;
        }
        tracing::info!("relay helper connected");
        serve_helper(stream, &mut link, &mut unsent, &state, &stop).await;
        tracing::warn!("relay helper disconnected; approval messages wait for it");
    }
}

async fn write(w: &mut tokio::net::unix::OwnedWriteHalf, value: &Value) -> bool {
    write_line(w, value.to_string().as_bytes(), WRITE_TIMEOUT).await
}

async fn serve_helper(
    stream: UnixStream,
    link: &mut RelayLink,
    unsent: &mut Option<Event>,
    state: &Shared,
    stop: &watch::Sender<bool>,
) {
    let (read, mut w) = stream.into_split();
    let mut reader = LineReader::new(read, MAX_RELAY_LINE);
    let filter = json!({
        "kinds": [1059],
        "#p": [hex::encode(link.channel)],
        "since": wall().saturating_sub(SINCE_SECS),
    });
    if !write(&mut w, &json!({ "relays": link.relays })).await
        || !write(&mut w, &json!({ "subscribe": filter })).await
    {
        return;
    }
    loop {
        if let Some(event) = unsent.take() {
            if !write(&mut w, &json!({ "publish": event })).await {
                *unsent = Some(event);
                return;
            }
        }
        tokio::select! {
            event = link.outbox.pop() => {
                *unsent = Some(event);
            }
            line = reader.next_line() => {
                let line = match line {
                    Ok(Some(line)) => line,
                    _ => return,
                };
                if !from_helper(&line, link, state, stop).await {
                    return;
                }
            }
        }
    }
}

/// Handle one line from the helper; `false` ends the connection.
async fn from_helper(
    line: &[u8],
    link: &RelayLink,
    state: &Shared,
    stop: &watch::Sender<bool>,
) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        tracing::warn!("the relay helper sent a line that is not JSON");
        return false;
    };
    if let Some(event) = value.get("event") {
        let Ok(event) = Event::from_json(event.to_string()) else {
            return true;
        };
        // Opened outside the state lock, in arrival order: one HMAC per
        // expected sender for a wrap not ours, a replay dropped before it is
        // decrypted again.
        let inbox = link.inbox.clone();
        let now = wall();
        let opened = tokio::task::spawn_blocking(move || lock(&inbox).open(&event, now))
            .await
            .ok()
            .flatten();
        if let Some(opened) = opened {
            if with_state(state, stop, move |s| s.approval_message(opened))
                .await
                .is_none()
            {
                return false;
            }
        }
        return true;
    }
    if let Some(id) = value.get("published") {
        let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
        if !ok {
            tracing::warn!(%id, "no relay took an approval message");
        }
        return true;
    }
    tracing::warn!("the relay helper sent a line the gateway does not know");
    true
}
