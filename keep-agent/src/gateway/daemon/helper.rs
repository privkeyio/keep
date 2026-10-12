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

use std::collections::HashMap;
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
use tokio::time::Instant;

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

/// Wraps one relay may pass on at once, and how many more each second after:
/// far above what approvals need, so a relay flooding the channel key uses
/// up only its own share, and what the other relays deliver still gets
/// through.
const RELAY_BURST: f64 = 512.0;
const RELAY_PER_SEC: f64 = 32.0;

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

/// What the helper passes on from the relays: gift wraps only, each relay
/// within its own share, and only lines the gateway reads.
#[derive(Default)]
struct Intake {
    /// Each relay's share left, and when it was last topped up.
    relays: HashMap<RelayUrl, (f64, Instant)>,
    dropped: u64,
}

/// What to do with one relay notification.
#[derive(Debug)]
enum Step {
    Forward(String),
    Skip,
    End(Result<()>),
}

impl Intake {
    /// Every copy a relay delivers is counted against that relay, not only
    /// the first one seen: otherwise a relay could pass on a wrap first, past
    /// its share, and keep the other relays' copies from ever counting.
    fn step(
        &mut self,
        notification: std::result::Result<RelayPoolNotification, RecvError>,
    ) -> Step {
        match notification {
            Ok(RelayPoolNotification::Message {
                relay_url,
                message: RelayMessage::Event { event, .. },
            }) if event.kind == Kind::GiftWrap => match self.line(&relay_url, &event) {
                Some(line) => Step::Forward(line),
                None => Step::Skip,
            },
            Ok(RelayPoolNotification::Shutdown) | Err(RecvError::Closed) => Step::End(Ok(())),
            Ok(_) => Step::Skip,
            // A fresh session subscribes again, and the relays send what was
            // missed.
            Err(RecvError::Lagged(n)) => Step::End(Err(AgentError::Other(format!(
                "{n} relay events were missed; subscribing again"
            )))),
        }
    }

    /// The line for `event` from `relay`, or `None` when `relay` used up its
    /// share or the line is longer than the gateway reads, which would end
    /// the connection every time the relay sent it again.
    fn line(&mut self, relay: &RelayUrl, event: &Event) -> Option<String> {
        let now = Instant::now();
        let (share, topped) = self
            .relays
            .entry(relay.clone())
            .or_insert((RELAY_BURST, now));
        *share =
            (*share + now.duration_since(*topped).as_secs_f64() * RELAY_PER_SEC).min(RELAY_BURST);
        *topped = now;
        if *share < 1.0 {
            self.dropped(relay, "the relay sent more than its share");
            return None;
        }
        *share -= 1.0;
        let line = json!({ "event": event }).to_string();
        if line.len() > MAX_RELAY_LINE {
            self.dropped(relay, "the wrap is larger than the gateway reads");
            return None;
        }
        Some(line)
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
    let (lines, mut queue) = mpsc::channel::<String>(256);
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
                        if let Err(e) = from_gateway(&client, &line, &lines, &mut publishes).await {
                            break Err(e);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(AgentError::Other(e.to_string())),
                }
            }
            Some(_) = publishes.join_next(), if !publishes.is_empty() => {}
            notification = notifications.recv() => {
                match intake.step(notification) {
                    Step::Forward(line) => {
                        if lines.send(line).await.is_err() {
                            break Ok(());
                        }
                    }
                    Step::Skip => {}
                    Step::End(result) => break result,
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
async fn from_gateway(
    client: &Client,
    line: &[u8],
    lines: &mpsc::Sender<String>,
    publishes: &mut JoinSet<()>,
) -> Result<()> {
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
        publishes.spawn(async move {
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
            let _ = lines
                .send(json!({ "published": id, "ok": ok }).to_string())
                .await;
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
        let mut publishes = JoinSet::new();
        let keys = nostr_sdk::prelude::Keys::generate();
        let note = nostr_sdk::prelude::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let line = json!({ "publish": note }).to_string();
        let refused = from_gateway(&client, line.as_bytes(), &lines, &mut publishes).await;
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

    /// A wrap whose line the gateway would refuse as too long is dropped
    /// here: passed on, it would end the connection, and the relay would
    /// send it again on every new subscription.
    #[tokio::test]
    async fn a_wrap_too_long_for_the_gateway_is_dropped() {
        let mut intake = Intake::default();
        let relay = "wss://a.example.com";
        let Step::Forward(line) = intake.step(delivered(relay, wrap("fits"))) else {
            panic!("a small wrap is passed on");
        };
        assert!(line.contains("fits"));
        let overhead = json!({ "event": wrap("") }).to_string().len();
        let most = wrap(&"x".repeat(MAX_RELAY_LINE - overhead));
        assert!(
            matches!(intake.step(delivered(relay, most)), Step::Forward(l) if l.len() == MAX_RELAY_LINE)
        );
        let over = wrap(&"x".repeat(MAX_RELAY_LINE - overhead + 1));
        assert!(matches!(intake.step(delivered(relay, over)), Step::Skip));
        let note = nostr_sdk::prelude::EventBuilder::text_note("hello")
            .sign_with_keys(&nostr_sdk::prelude::Keys::generate())
            .unwrap();
        assert!(matches!(intake.step(delivered(relay, note)), Step::Skip));
    }

    /// A relay flooding the channel key uses up its own share only: another
    /// relay's wraps still go through, and the flooding relay's share comes
    /// back with time.
    #[tokio::test(start_paused = true)]
    async fn one_relay_flooding_uses_up_only_its_own_share() {
        let mut intake = Intake::default();
        let (a, b) = ("wss://a.example.com", "wss://b.example.com");
        let event = wrap("x");
        let forwarded = |intake: &mut Intake, relay: &str, n: usize| {
            (0..n)
                .filter(|_| {
                    matches!(
                        intake.step(delivered(relay, event.clone())),
                        Step::Forward(_)
                    )
                })
                .count()
        };
        assert_eq!(forwarded(&mut intake, a, 2_000), RELAY_BURST as usize);
        assert_eq!(
            forwarded(&mut intake, b, 10),
            10,
            "another relay is unaffected"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(forwarded(&mut intake, a, 2_000), RELAY_PER_SEC as usize);
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
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
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
}
