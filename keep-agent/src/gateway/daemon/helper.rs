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

use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

use nostr_sdk::prelude::{
    Client, Event, Filter, JsonUtil, Kind, RelayMessage, RelayOptions, RelayPoolNotification,
    RelayUrl,
};
use serde_json::{json, Value};
use tokio::net::UnixStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

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

/// How long publishes still under way may go on once the connection to the
/// gateway ends, so what it sent as it stopped (outcomes, the last anchor)
/// still goes out; then they are dropped and the helper connects again.
const PUBLISH_FLUSH: Duration = Duration::from_secs(3);

/// The most one relay's wraps waiting for the gateway may take, in bytes of
/// their lines. Wraps go to the gateway as fast as it reads them, so a queue
/// fills only while the gateway is behind.
const RELAY_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Lines on their way to the gateway's socket, past the relays' queues.
const GATEWAY_QUEUE: usize = 16;

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

/// What the helper passes on from the relays: gift wraps the gateway can
/// read, each relay's in a queue of its own, taken in turn as fast as the
/// gateway reads them. Nothing is dropped for coming fast: the gateway turns
/// away a wrap without a valid tag with a few HMACs, and a valid one may be
/// a decision that is never sent again. Only when a relay's queue is full,
/// because the gateway is behind, does that relay lose its oldest wrap, the
/// one longest past its time: decisions are live, while a flood replays a
/// relay's stored backlog. A relay flooding fills only its own queue, so the
/// others' wraps still get their turn.
#[derive(Default)]
struct Intake {
    /// Each relay's queue: its lines, oldest first, and their bytes.
    relays: Vec<(RelayUrl, VecDeque<String>, usize)>,
    /// The relay whose turn is next.
    turn: usize,
    dropped: u64,
}

/// What to do with one relay notification.
#[derive(Debug)]
enum Step {
    Go,
    End(Result<()>),
}

impl Intake {
    /// Every copy a relay delivers goes to that relay's queue, not only the
    /// first one seen: otherwise a relay could pass on a wrap first, then
    /// lose it from its full queue, and keep the other relays' copies from
    /// ever counting.
    fn step(
        &mut self,
        notification: std::result::Result<RelayPoolNotification, RecvError>,
    ) -> Step {
        match notification {
            Ok(RelayPoolNotification::Message {
                relay_url,
                message: RelayMessage::Event { event, .. },
            }) if event.kind == Kind::GiftWrap => {
                self.push(&relay_url, &event);
                Step::Go
            }
            Ok(RelayPoolNotification::Shutdown) | Err(RecvError::Closed) => Step::End(Ok(())),
            Ok(_) => Step::Go,
            // A fresh session subscribes again, and the relays send what was
            // missed.
            Err(RecvError::Lagged(n)) => Step::End(Err(AgentError::Other(format!(
                "{n} relay events were missed; subscribing again"
            )))),
        }
    }

    /// Queue `event` from `relay`, unless its line is longer than the
    /// gateway reads, which would end the connection every time the relay
    /// sent it again.
    fn push(&mut self, relay: &RelayUrl, event: &Event) {
        let line = json!({ "event": event }).to_string();
        if line.len() > MAX_RELAY_LINE {
            self.dropped(relay, "the wrap is larger than the gateway reads");
            return;
        }
        let at = match self.relays.iter().position(|(url, _, _)| url == relay) {
            Some(at) => at,
            None => {
                self.relays.push((relay.clone(), VecDeque::new(), 0));
                self.relays.len() - 1
            }
        };
        let mut lost = 0;
        let (_, queue, bytes) = &mut self.relays[at];
        while *bytes + line.len() > RELAY_QUEUE_BYTES {
            let Some(oldest) = queue.pop_front() else {
                break;
            };
            *bytes -= oldest.len();
            lost += 1;
        }
        *bytes += line.len();
        queue.push_back(line);
        for _ in 0..lost {
            self.dropped(
                relay,
                "the gateway is behind and the relay's queue is full: its oldest wrap went",
            );
        }
    }

    /// The next line for the gateway, from each relay in turn.
    fn pop(&mut self) -> Option<String> {
        for _ in 0..self.relays.len() {
            let at = self.turn % self.relays.len();
            self.turn = at + 1;
            let (_, queue, bytes) = &mut self.relays[at];
            if let Some(line) = queue.pop_front() {
                *bytes -= line.len();
                return Some(line);
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.relays.iter().all(|(_, queue, _)| queue.is_empty())
    }

    fn dropped(&mut self, relay: &RelayUrl, why: &str) {
        self.dropped += 1;
        if self.dropped.is_power_of_two() {
            tracing::warn!(%relay, dropped = self.dropped, why, "a relay event was dropped");
        }
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
    let (lines, mut queue) = mpsc::channel::<String>(GATEWAY_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(line) = queue.recv().await {
            if !write_line(&mut write, line.as_bytes(), WRITE_TIMEOUT).await {
                return;
            }
        }
    });
    let client = Client::default();
    let mut notifications = client.notifications();
    let mut publishes = JoinSet::new();
    let mut intake = Intake::default();
    let result = loop {
        tokio::select! {
            line = reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if let Err(e) = from_gateway(&client, &line, &mut publishes).await {
                            break Err(e);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(AgentError::Other(e.to_string())),
                }
            }
            Some(_) = publishes.join_next(), if !publishes.is_empty() => {}
            notification = notifications.recv() => {
                if let Step::End(result) = intake.step(notification) {
                    break result;
                }
            }
            // As fast as the gateway reads, never waiting on it here: the
            // notifications go on being taken meanwhile.
            permit = lines.reserve(), if !intake.is_empty() => {
                match (permit, intake.pop()) {
                    (Ok(permit), Some(line)) => permit.send(line),
                    (Ok(_), None) => {}
                    (Err(_), _) => break Ok(()),
                }
            }
        }
    };
    // The publishes hold the line queue open, and with it the writer: they
    // get a bounded moment, then go, so the helper connects again at once.
    let _ = tokio::time::timeout(PUBLISH_FLUSH, async {
        while publishes.join_next().await.is_some() {}
    })
    .await;
    publishes.shutdown().await;
    writer.abort();
    let _ = writer.await;
    client.shutdown().await;
    result
}

/// Handle one line from the gateway.
async fn from_gateway(client: &Client, line: &[u8], publishes: &mut JoinSet<()>) -> Result<()> {
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
        let client = client.clone();
        publishes.spawn(async move {
            let id = event.id.to_hex();
            let mut wait = Duration::from_secs(1);
            let give_up = tokio::time::Instant::now() + PUBLISH_RETRY_FOR;
            loop {
                match client.send_event(&event).await {
                    Ok(output) if !output.success.is_empty() => return,
                    Ok(_) => tracing::warn!(%id, "no relay took an approval message yet"),
                    Err(e) => {
                        tracing::warn!(%id, error = %e, "an approval message was not published yet")
                    }
                }
                if tokio::time::Instant::now() + wait > give_up {
                    tracing::warn!(%id, "no relay took an approval message; giving up");
                    return;
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(MAX_BACKOFF);
            }
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
        let mut publishes = JoinSet::new();
        let keys = nostr_sdk::prelude::Keys::generate();
        let note = nostr_sdk::prelude::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let line = json!({ "publish": note }).to_string();
        let refused = from_gateway(&client, line.as_bytes(), &mut publishes).await;
        assert!(refused
            .unwrap_err()
            .to_string()
            .contains("other than a gift wrap"),);
    }

    fn wrap(content: &str) -> Event {
        nostr_sdk::prelude::EventBuilder::new(Kind::GiftWrap, content)
            .sign_with_keys(&nostr_sdk::prelude::Keys::generate())
            .unwrap()
    }

    fn delivered(
        relay: &str,
        event: Event,
    ) -> std::result::Result<RelayPoolNotification, RecvError> {
        Ok(RelayPoolNotification::Message {
            relay_url: RelayUrl::parse(relay).unwrap(),
            message: RelayMessage::Event {
                subscription_id: std::borrow::Cow::Owned(nostr_sdk::prelude::SubscriptionId::new(
                    "s",
                )),
                event: std::borrow::Cow::Owned(event),
            },
        })
    }

    fn drain(intake: &mut Intake) -> Vec<String> {
        std::iter::from_fn(|| intake.pop()).collect()
    }

    /// A wrap whose line the gateway would refuse as too long is dropped
    /// here: passed on, it would end the connection, and the relay would
    /// send it again on every new subscription.
    #[test]
    fn a_wrap_too_long_for_the_gateway_is_dropped() {
        let mut intake = Intake::default();
        let relay = "wss://a.example.com";
        let overhead = json!({ "event": wrap("") }).to_string().len();
        for event in [
            wrap("fits"),
            wrap(&"x".repeat(MAX_RELAY_LINE - overhead)),
            wrap(&"x".repeat(MAX_RELAY_LINE - overhead + 1)),
        ] {
            assert!(matches!(intake.step(delivered(relay, event)), Step::Go));
        }
        let note = nostr_sdk::prelude::EventBuilder::text_note("hello")
            .sign_with_keys(&nostr_sdk::prelude::Keys::generate())
            .unwrap();
        intake.step(delivered(relay, note));
        let lines: Vec<usize> = drain(&mut intake).iter().map(String::len).collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[1], MAX_RELAY_LINE);
    }

    /// A flood through every relay, however fast, loses nothing while the
    /// gateway keeps up: a valid wrap among it still gets through. Each relay
    /// gets its turn, so one flooding still cannot crowd out another's copy,
    /// and only once a relay's own queue is full does it lose its oldest.
    #[test]
    fn a_flood_loses_nothing_while_the_gateway_keeps_up_and_each_relay_gets_its_turn() {
        let relays = [
            "wss://a.example.com",
            "wss://b.example.com",
            "wss://c.example.com",
        ];
        // Large enough that 3,000 overflow a relay's queue.
        let pad = "x".repeat(2_000);
        let junk: Vec<Event> = (0..3_000)
            .map(|i| wrap(&format!("junk {i} {pad}")))
            .collect();
        let is = |line: &str, i: usize| line.contains(&format!("\"junk {i} "));
        let valid = wrap("a decision");
        let mut intake = Intake::default();
        let mut through = 0;
        let mut found = false;
        for (i, event) in junk.iter().enumerate() {
            for relay in relays {
                intake.step(delivered(relay, event.clone()));
            }
            if i == 2_000 {
                intake.step(delivered(relays[1], valid.clone()));
            }
            // The gateway reads as fast as the wraps come.
            for _ in 0..4 {
                if let Some(line) = intake.pop() {
                    through += 1;
                    found |= line.contains("a decision");
                }
            }
        }
        through += drain(&mut intake).len();
        assert!(found, "the valid wrap got through");
        assert_eq!(through, 3 * junk.len() + 1, "nothing was dropped");
        assert_eq!(intake.dropped, 0);

        // One relay floods past its queue while the gateway is behind: it
        // loses its own oldest, and the other relay's copy comes next.
        let mut intake = Intake::default();
        for event in &junk {
            intake.step(delivered(relays[0], event.clone()));
        }
        assert!(intake.dropped > 0, "the queue filled");
        let kept = intake.relays[0].1.len();
        assert!(is(intake.relays[0].1.back().unwrap(), junk.len() - 1));
        intake.step(delivered(relays[1], valid.clone()));
        let first = intake.pop().unwrap();
        assert!(is(&first, junk.len() - kept), "the oldest went");
        assert!(intake.pop().unwrap().contains("a decision"));
        let full = intake.relays[0].2;
        assert!(full <= RELAY_QUEUE_BYTES && full + 2 * first.len() > RELAY_QUEUE_BYTES);
    }

    /// Relay events missed because the helper fell behind end the session,
    /// so a fresh one subscribes again and the relays send them again.
    #[test]
    fn missed_relay_events_end_the_session() {
        let mut intake = Intake::default();
        assert!(matches!(
            intake.step(Err(RecvError::Lagged(3))),
            Step::End(Err(_))
        ));
        assert!(matches!(
            intake.step(Err(RecvError::Closed)),
            Step::End(Ok(()))
        ));
    }

    fn socket_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        dir
    }

    fn run(
        path: &Path,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let path = path.to_path_buf();
        let me = rustix::process::geteuid().as_raw();
        let helper = tokio::spawn(async move {
            helper_loop(&path, me, async {
                let _ = stopped.await;
            })
            .await
        });
        (stop, helper)
    }

    async fn send(stream: &mut UnixStream, value: Value) {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
    }

    /// A publish no relay takes does not hold the helper once the gateway
    /// goes away: it connects again within moments, not once the publish
    /// gives up minutes later.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_helper_connects_again_soon_after_the_gateway_goes_away() {
        let dir = socket_dir();
        let path = dir.path().join("relay.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stop, helper) = run(&path);
        let (mut first, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        send(&mut first, json!({ "publish": wrap("x") })).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(first);
        let gone = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(15), listener.accept())
            .await
            .expect("the helper connects again soon")
            .unwrap();
        assert!(gone.elapsed() < PUBLISH_FLUSH + Duration::from_secs(5));
        let _ = stop.send(());
        helper.await.unwrap().unwrap();
    }

    /// What the gateway asked to publish just before it went away still
    /// reaches the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_publish_under_way_when_the_gateway_goes_away_still_goes_out() {
        let relay = crate::gateway::daemon::test_relay::start_mock_relay().await;
        let url = relay.url().await.to_string();
        let dir = socket_dir();
        let path = dir.path().join("relay.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stop, helper) = run(&path);
        let (mut gateway, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let last = wrap("the last outcome");
        send(&mut gateway, json!({ "relays": [url] })).await;
        send(&mut gateway, json!({ "publish": last })).await;
        drop(gateway);
        let reader = Client::default();
        reader.add_relay(&url).await.unwrap();
        reader.connect().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let found = reader
                .fetch_events(Filter::new().id(last.id), Duration::from_secs(2))
                .await
                .unwrap();
            if !found.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the publish never reached the relay"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = stop.send(());
        helper.await.unwrap().unwrap();
    }

    /// Through real relays, a flood through every relay far faster than any
    /// fixed rate (thousands of wraps a second) still lets a valid wrap
    /// through to a gateway that reads as fast as they come.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_flood_through_every_relay_still_lets_a_valid_wrap_through() {
        use nostr_relay_builder::builder::RateLimit;
        use nostr_relay_builder::{LocalRelay, RelayBuilder};
        use nostr_sdk::prelude::{EventBuilder, Keys, Tag};
        use tokio::io::AsyncBufReadExt;
        const PER_RELAY: usize = 3_000;
        // Retried for the same port race as `test_relay::start_mock_relay`, and
        // the relay is rebuilt per attempt because that is what draws a new
        // port.
        let relay = || async {
            let mut last = None;
            for _ in 0..8 {
                let relay = LocalRelay::new(RelayBuilder::default().rate_limit(RateLimit {
                    max_reqs: 500,
                    notes_per_minute: 100_000_000,
                }));
                match relay.run().await {
                    Ok(()) => return relay,
                    Err(e) => last = Some(e),
                }
            }
            panic!(
                "rate-limited relay start: {}",
                last.expect("a failure to report")
            );
        };
        // Kept to the end: a relay dropped stops serving subscriptions.
        let relays = [relay().await, relay().await];
        let urls = [
            relays[0].url().await.to_string(),
            relays[1].url().await.to_string(),
        ];
        let channel = Keys::generate().public_key();
        let gift = |content: String| {
            EventBuilder::new(Kind::GiftWrap, content)
                .tag(Tag::public_key(channel))
                .sign_with_keys(&Keys::generate())
                .unwrap()
        };
        let junk: Vec<Event> = (0..PER_RELAY).map(|i| gift(format!("junk {i}"))).collect();
        let valid = gift("a decision".into());

        let dir = socket_dir();
        let path = dir.path().join("relay.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stop, helper) = run(&path);
        let (mut gateway, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        send(&mut gateway, json!({ "relays": urls })).await;
        send(
            &mut gateway,
            json!({ "subscribe": { "kinds": [1059], "#p": [channel.to_hex()] } }),
        )
        .await;
        let want = valid.id.to_hex();
        let (read, _write) = gateway.into_split();
        let reader = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(read).lines();
            let mut seen = 0usize;
            while let Ok(Some(line)) = lines.next_line().await {
                seen += 1;
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["event"]["id"].as_str() == Some(want.as_str()) {
                    return Some(seen);
                }
            }
            None
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let started = std::time::Instant::now();
        let mut floods = JoinSet::new();
        for (r, url) in urls.iter().enumerate() {
            for part in junk.chunks(PER_RELAY / 8) {
                let (url, part) = (url.clone(), part.to_vec());
                let valid = (r == 1 && part[0] == junk[PER_RELAY / 2]).then(|| valid.clone());
                floods.spawn(async move {
                    let client = Client::default();
                    client.add_relay(&url).await.unwrap();
                    client.connect().await;
                    client.wait_for_connection(Duration::from_secs(5)).await;
                    for event in &part {
                        client.send_event(event).await.unwrap();
                    }
                    if let Some(valid) = valid {
                        client.send_event(&valid).await.unwrap();
                    }
                    client.shutdown().await;
                });
            }
        }
        while let Some(done) = floods.join_next().await {
            done.unwrap();
        }
        let rate = (2 * PER_RELAY) as f64 / started.elapsed().as_secs_f64();
        eprintln!("flooded {} wraps at {rate:.0} a second", 2 * PER_RELAY);
        let seen = tokio::time::timeout(Duration::from_secs(30), reader)
            .await
            .expect("the valid wrap reached the gateway in time")
            .unwrap();
        assert!(seen.is_some(), "the valid wrap reached the gateway");
        let _ = stop.send(());
        helper.await.unwrap().unwrap();
    }
}
