// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Approvals over a real relay: the gateway on its sockets, the relay helper
//! on the relay socket, a mock relay, and a phone that talks to the relay
//! with its own client, as keep-android will.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use keep_approval::change::Scope;
use keep_approval::messages::{self as wire, Request, Verdict};
use keep_approval::{kind, Hex32};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::{Client, Event, Filter, Kind, PublicKey, RelayPoolNotification};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::approval_tests::{channel, Phone};
use super::approvals::{Store, StoredDevice};
use super::clock::tests::FakeBoot;
use super::server::{self, Limits};
use super::state::Settings;
use super::tests::{nostr_grant, start, vault, BOOT};

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn socket_dir(root: &std::path::Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    dir
}

/// A phone on the relay: what it receives arrives through a subscription,
/// what it sends goes out with its own client.
struct OnRelay {
    phone: Phone,
    client: Client,
    events: tokio::sync::broadcast::Receiver<RelayPoolNotification>,
}

impl OnRelay {
    async fn new(phone: Phone, url: &str) -> Self {
        let client = Client::default();
        client.add_relay(url).await.unwrap();
        client.connect().await;
        let events = client.notifications();
        let me = PublicKey::from_slice(&phone.t()).unwrap();
        client
            .subscribe(Filter::new().kind(Kind::GiftWrap).pubkey(me), None)
            .await
            .unwrap();
        Self {
            phone,
            client,
            events,
        }
    }

    /// The next message of `want` the gateway sent this phone.
    async fn next(&mut self, want: u16) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let notification = tokio::time::timeout_at(deadline, self.events.recv())
                .await
                .expect("a message from the gateway in time")
                .unwrap();
            if let RelayPoolNotification::Event { event, .. } = notification {
                let now = super::clock::wall_clock().unwrap();
                for (kind, content) in self.phone.open(&[*event], now) {
                    if kind == want {
                        return content;
                    }
                }
            }
        }
    }

    /// The next anchor that shows `frozen` for the whole gateway.
    async fn anchor_showing(&mut self, frozen: bool) -> wire::Anchor {
        loop {
            let anchor: wire::Anchor = wire::parse(&self.next(kind::ANCHOR).await).unwrap();
            if anchor.frozen.all == frozen {
                return anchor;
            }
        }
    }

    async fn send(&self, kind: u16, content: &str) {
        let now = super::clock::wall_clock().unwrap();
        let event: Event = self.phone.wrap(kind, content, now);
        self.client.send_event(&event).await.unwrap();
    }
}

async fn line(read: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>) -> Value {
    let next = tokio::time::timeout(Duration::from_secs(30), read.next_line())
        .await
        .expect("an answer in time")
        .unwrap()
        .expect("not closed");
    serde_json::from_str(&next).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_travel_through_the_helper_and_a_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let (agent_dir, admin_dir, relay_dir) = (
        socket_dir(root.path(), "agent"),
        socket_dir(root.path(), "admin"),
        socket_dir(root.path(), "relay"),
    );
    let (keep, key) = vault(root.path());
    let phone = Phone::new();
    let can_hold = keep_core::agent::bindable_uid(uid);
    let boot = FakeBoot::default();
    // The phone's clock is the real one: the gateway's must be too, or its
    // wraps fall outside the phone's time window.
    boot.set_wall(super::clock::wall_clock().unwrap());
    // A credential for this test's uid when it may hold one, issued before
    // the phone is registered; then the phone, as pairing leaves it.
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    let token = can_hold.then(|| {
        let answer = state.admin_request(
            json!({ "op": "issue", "name": "agent", "uid": uid, "grant": nostr_grant(key) })
                .to_string()
                .as_bytes(),
        );
        let answer: Value = serde_json::from_str(&answer).unwrap();
        answer["token"].as_str().unwrap().to_string()
    });
    Store {
        channel: Some(Hex32(channel().public_key().to_bytes())),
        devices: vec![StoredDevice {
            transport: Hex32(phone.t()),
            alg: keep_approval::sig::Alg::P256,
            approver: keep_approval::Hex33(phone.a()),
            label: "Phone".into(),
            counter: 0,
        }],
        ..Store::default()
    }
    .save(state.keep_mut())
    .unwrap();
    state
        .configure_approvals(Some(channel()), vec![url.clone()], 60)
        .unwrap();
    let (agent, admin, relay_socket) = (
        agent_dir.join("agent.sock"),
        admin_dir.join("admin.sock"),
        relay_dir.join("relay.sock"),
    );
    let agent_listener = server::bind(&agent, uid).unwrap();
    let admin_listener = server::bind(&admin, uid).unwrap();
    let relay_listener = server::bind(&relay_socket, uid).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let gateway = tokio::spawn(server::serve(
        state,
        agent_listener,
        admin_listener,
        Some((relay_listener, uid)),
        Limits {
            admin_idle: Duration::from_secs(60),
            ..Limits::default()
        },
        async {
            let _ = stopped.await;
        },
    ));
    let (helper_stop, helper_stopped) = tokio::sync::oneshot::channel::<()>();
    let helper_socket = relay_socket.clone();
    let helper = tokio::spawn(async move {
        super::helper::helper_loop(&helper_socket, uid, async {
            let _ = helper_stopped.await;
        })
        .await
    });
    let mut phone = OnRelay::new(phone, &url).await;

    let first = phone.anchor_showing(false).await;
    // Root reaches the admin socket (a uid that may hold a credential is not
    // an admin): a management change over it waits for the phone.
    let epoch = if uid == 0 {
        let (read, mut write) = UnixStream::connect(&admin).await.unwrap().into_split();
        let mut read = BufReader::new(read).lines();
        write.write_all(b"{\"op\":\"freeze_all\"}\n").await.unwrap();
        assert_eq!(line(&mut read).await["ok"], json!(true));
        phone.anchor_showing(true).await;
        write
            .write_all(b"{\"op\":\"unfreeze_all\"}\n")
            .await
            .unwrap();
        let answer = line(&mut read).await;
        assert!(answer["pending"].is_string(), "{answer}");
        let request: Request = wire::parse(&phone.next(kind::REQUEST).await).unwrap();
        keep_approval::binding::check_request(&request, &phone.phone.channel).unwrap();
        phone
            .send(
                kind::DECISION,
                &phone.phone.decide(&request, Verdict::Approve),
            )
            .await;
        let answer = line(&mut read).await;
        assert_eq!(answer["ok"], json!(true), "{answer}");
        assert_eq!(answer["result"]["unfrozen"], json!("all"));
        let epoch = phone.anchor_showing(false).await.frozen.epoch;
        assert_eq!(epoch, first.frozen.epoch + 2);
        epoch
    } else {
        first.frozen.epoch
    };

    // A freeze from the phone, over the relay, and its unfreeze.
    let freeze = phone.phone.freeze(Scope::All, epoch);
    phone.send(kind::FREEZE, &freeze).await;
    let anchor = phone.anchor_showing(true).await;
    assert_eq!(anchor.frozen.epoch, epoch + 1);
    let unfreeze = phone.phone.unfreeze(Scope::All, anchor.frozen.epoch);
    phone.send(kind::FREEZE, &unfreeze).await;
    let anchor = phone.anchor_showing(false).await;
    assert_eq!(anchor.frozen.epoch, epoch + 2);

    if let Some(token) = token {
        // An agent's request, approved on the phone, answered on its socket.
        let (read, mut write) = UnixStream::connect(&agent).await.unwrap().into_split();
        let mut agent_read = BufReader::new(read).lines();
        let call = |id: u64| {
            json!({ "token": token, "message": {
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": "sign_nostr_event", "arguments": { "kind": 0, "content": "{}" } }
            }})
            .to_string()
                + "\n"
        };
        write.write_all(call(1).as_bytes()).await.unwrap();
        let request: Request = wire::parse(&phone.next(kind::REQUEST).await).unwrap();
        phone
            .send(
                kind::DECISION,
                &phone.phone.decide(&request, Verdict::Approve),
            )
            .await;
        let answer = line(&mut agent_read).await;
        assert_eq!(answer["id"], json!(1));
        assert_eq!(answer["result"]["isError"], json!(false), "{answer}");

        // The agent going away withdraws what it waits for.
        write.write_all(call(2).as_bytes()).await.unwrap();
        let request: Request = wire::parse(&phone.next(kind::REQUEST).await).unwrap();
        drop(write);
        drop(agent_read);
        let outcome: wire::Outcome = wire::parse(&phone.next(kind::OUTCOME).await).unwrap();
        // The approval of the first request is announced first.
        let outcome = if outcome.request_id == request.request_id {
            outcome
        } else {
            wire::parse(&phone.next(kind::OUTCOME).await).unwrap()
        };
        assert_eq!(outcome.request_id, request.request_id);
        assert_eq!(outcome.outcome, wire::OutcomeKind::Canceled);
    } else {
        eprintln!("skipped the agent socket part: this test's uid cannot hold a credential");
    }

    let _ = helper_stop.send(());
    helper.await.unwrap().unwrap();
    let _ = stop.send(());
    gateway.await.unwrap().unwrap();
}

/// The relay socket serves only the relay helper's user: anyone else is
/// closed on, unanswered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_socket_turns_away_any_other_user() {
    use tokio::io::AsyncReadExt;
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let dir = socket_dir(root.path(), "relay");
    let (keep, _) = vault(root.path());
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let link = state.take_relay_link().unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    let (_closing, closed) = tokio::sync::watch::channel(false);
    let socket = dir.join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener,
        uid.wrapping_add(1),
        link,
        shared,
        stop,
        closed,
    ));
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0))), "{read:?} {buf:?}");
    task.abort();
}

/// A gateway that stops answers whoever waits on an approver with the
/// documented cancellation, and hands the helper the outcome for the
/// phones, before it returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopping_gateway_answers_what_waits_and_hands_the_helper_the_outcome() {
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    if !keep_core::agent::bindable_uid(uid) {
        eprintln!("skipped: this test's uid cannot hold a credential");
        return;
    }
    let (agent_dir, admin_dir, relay_dir) = (
        socket_dir(root.path(), "agent"),
        socket_dir(root.path(), "admin"),
        socket_dir(root.path(), "relay"),
    );
    let (keep, key) = vault(root.path());
    let mut phone = Phone::new();
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    let answer = state.admin_request(
        json!({ "op": "issue", "name": "agent", "uid": uid, "grant": nostr_grant(key) })
            .to_string()
            .as_bytes(),
    );
    let answer: Value = serde_json::from_str(&answer).unwrap();
    let token = answer["token"].as_str().unwrap().to_string();
    Store {
        channel: Some(Hex32(channel().public_key().to_bytes())),
        devices: vec![StoredDevice {
            transport: Hex32(phone.t()),
            alg: keep_approval::sig::Alg::P256,
            approver: keep_approval::Hex33(phone.a()),
            label: "Phone".into(),
            counter: 0,
        }],
        ..Store::default()
    }
    .save(state.keep_mut())
    .unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let (agent, admin, relay_socket) = (
        agent_dir.join("agent.sock"),
        admin_dir.join("admin.sock"),
        relay_dir.join("relay.sock"),
    );
    let std_listener = |path: &std::path::Path| {
        let listener = server::bind(path, uid).unwrap().into_std().unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    };
    let agent_listener = std_listener(&agent);
    let admin_listener = std_listener(&admin);
    let relay_listener = std_listener(&relay_socket);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    // On a runtime of its own, dropped once the gateway returns, as when the
    // daemon exits: whatever it has not written by then is never written.
    let gateway = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let agent_listener = tokio::net::UnixListener::from_std(agent_listener).unwrap();
            let admin_listener = tokio::net::UnixListener::from_std(admin_listener).unwrap();
            let relay_listener = tokio::net::UnixListener::from_std(relay_listener).unwrap();
            server::serve(
                state,
                agent_listener,
                admin_listener,
                Some((relay_listener, uid)),
                Limits::default(),
                async {
                    let _ = stopped.await;
                },
            )
            .await
        })
    });
    // This test is the relay helper.
    let (read, _write) = UnixStream::connect(&relay_socket)
        .await
        .unwrap()
        .into_split();
    let mut helper = BufReader::new(read).lines();
    assert!(line(&mut helper).await.get("relays").is_some());
    assert!(line(&mut helper).await.get("subscribe").is_some());
    let opened = |phone: &mut Phone, value: &Value| -> Vec<(u16, String)> {
        let event: Event = serde_json::from_value(value["publish"].clone()).unwrap();
        phone.open(&[event], super::clock::wall_clock().unwrap())
    };

    let (read, mut write) = UnixStream::connect(&agent).await.unwrap().into_split();
    let mut agent_read = BufReader::new(read).lines();
    let call = json!({ "token": token, "message": {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "sign_nostr_event", "arguments": { "kind": 0, "content": "{}" } }
    }})
    .to_string()
        + "\n";
    write.write_all(call.as_bytes()).await.unwrap();
    let request: Request = loop {
        let got = opened(&mut phone, &line(&mut helper).await);
        if let Some((_, text)) = got.into_iter().find(|(k, _)| *k == kind::REQUEST) {
            break wire::parse(&text).unwrap();
        }
    };

    let _ = stop.send(());
    // Well within the bound a connection that ignored the stop would take.
    tokio::time::timeout(
        Duration::from_secs(8),
        tokio::task::spawn_blocking(move || gateway.join()),
    )
    .await
    .expect("the gateway stops in time")
    .unwrap()
    .unwrap()
    .unwrap();
    // All of it was written before the gateway returned.
    let quick = Duration::from_secs(1);
    let answer = tokio::time::timeout(quick, agent_read.next_line())
        .await
        .expect("answered before the gateway returned")
        .unwrap()
        .expect("an answer");
    let answer: Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(answer["id"], json!(1));
    let text = answer["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("canceled: the gateway is stopping"),
        "{answer}"
    );
    assert!(tokio::time::timeout(quick, agent_read.next_line())
        .await
        .expect("closed before the gateway returned")
        .unwrap()
        .is_none());
    let mut canceled = false;
    while let Some(next) = tokio::time::timeout(quick, helper.next_line())
        .await
        .expect("the relay connection closed before the gateway returned")
        .unwrap()
    {
        let value: Value = serde_json::from_str(&next).unwrap();
        for (k, text) in opened(&mut phone, &value) {
            if k == kind::OUTCOME {
                let outcome: wire::Outcome = wire::parse(&text).unwrap();
                canceled |= outcome.request_id == request.request_id
                    && outcome.outcome == wire::OutcomeKind::Canceled;
            }
        }
    }
    assert!(canceled, "the helper got the cancellation for the phones");
}

/// As the gateway stops, the relay task hands the helper everything still
/// queued, then returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_task_hands_over_what_is_queued_as_the_gateway_stops() {
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let dir = socket_dir(root.path(), "relay");
    let (keep, _) = vault(root.path());
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let now = state.calendar();
    let link = state.take_relay_link().unwrap();
    let outbox = link.outbox.clone();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    let (closing, closed) = tokio::sync::watch::channel(false);
    let socket = dir.join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener, uid, link, shared, stop, closed,
    ));
    let (read, _write) = UnixStream::connect(&socket).await.unwrap().into_split();
    let mut helper = BufReader::new(read).lines();
    assert!(line(&mut helper).await.get("relays").is_some());
    assert!(line(&mut helper).await.get("subscribe").is_some());
    let keys = nostr_sdk::prelude::Keys::generate();
    let queued: Vec<Event> = (0..50)
        .map(|i| {
            nostr_sdk::prelude::EventBuilder::new(Kind::GiftWrap, format!("{i}"))
                .sign_with_keys(&keys)
                .unwrap()
        })
        .collect();
    for event in &queued {
        outbox.push(event.clone(), super::approvals::Carries::Other, now);
    }
    closing.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the relay task returns")
        .unwrap();
    let mut published = Vec::new();
    while let Some(next) = helper.next_line().await.unwrap() {
        let value: Value = serde_json::from_str(&next).unwrap();
        published.push(value["publish"]["id"].as_str().unwrap().to_string());
    }
    let ids: Vec<String> = queued.iter().map(|e| e.id.to_hex()).collect();
    assert_eq!(published, ids);

    // With no helper connected, it returns at once.
    std::fs::create_dir(root.path().join("second")).unwrap();
    let (keep, _) = vault(&root.path().join("second"));
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let link = state.take_relay_link().unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    let (closing, closed) = tokio::sync::watch::channel(false);
    let socket = socket_dir(root.path(), "relay2").join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener, uid, link, shared, stop, closed,
    ));
    closing.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("the relay task returns at once")
        .unwrap();
}

/// The relay socket serves one helper at a time: a second connection waits,
/// unserved, until the first one ends, and is served then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_socket_serves_one_helper_at_a_time() {
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let dir = socket_dir(root.path(), "relay");
    let (keep, _) = vault(root.path());
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let link = state.take_relay_link().unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    let (_closing, closed) = tokio::sync::watch::channel(false);
    let socket = dir.join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener, uid, link, shared, stop, closed,
    ));
    let connect = || async {
        let (read, write) = UnixStream::connect(&socket).await.unwrap().into_split();
        (BufReader::new(read).lines(), write)
    };
    let (mut first, first_write) = connect().await;
    assert!(line(&mut first).await.get("relays").is_some());
    let (mut second, _second_write) = connect().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), second.next_line())
            .await
            .is_err(),
        "a second helper is not served while the first is"
    );
    drop(first_write);
    drop(first);
    assert!(line(&mut second).await.get("relays").is_some());
    task.abort();
}

/// How fast the gateway takes junk wraps off the relay socket: wraps for the
/// channel key carrying a well-formed tag of no expected sender, the most a
/// flood can make it do short of a device's tag key. Each costs a parse and
/// one HMAC per device before it is dropped. The helper's queues drain at
/// this rate, so a flood slower than it loses nothing. What is checked is
/// only that a valid wrap behind the junk is still taken; the rate is
/// printed, not gated, as it depends on the machine: about 4,900 a second in
/// a debug build and 38,000 in a release build on a 16-thread laptop under
/// load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gateway_turns_away_junk_wraps_quickly() {
    use nostr_sdk::prelude::{EventBuilder, Keys, Tag, TagKind};
    const JUNK: usize = 20_000;
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let dir = socket_dir(root.path(), "relay");
    let (keep, _) = vault(root.path());
    let mut phone = Phone::new();
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    let mut state = start(keep, Settings::default(), &boot, BOOT).unwrap();
    Store {
        channel: Some(Hex32(channel().public_key().to_bytes())),
        devices: vec![StoredDevice {
            transport: Hex32(phone.t()),
            alg: keep_approval::sig::Alg::P256,
            approver: keep_approval::Hex33(phone.a()),
            label: "Phone".into(),
            counter: 0,
        }],
        ..Store::default()
    }
    .save(state.keep_mut())
    .unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let epoch = state.keep().agent_freeze_epoch().unwrap();
    let link = state.take_relay_link().unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    let (_closing, closed) = tokio::sync::watch::channel(false);
    let socket = dir.join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener, uid, link, shared, stop, closed,
    ));
    let (read, mut write) = UnixStream::connect(&socket).await.unwrap().into_split();
    let mut helper = BufReader::new(read).lines();
    assert!(line(&mut helper).await.get("relays").is_some());
    assert!(line(&mut helper).await.get("subscribe").is_some());

    let content = "A".repeat(1_200);
    let keys = Keys::generate();
    let mut lines = Vec::with_capacity(JUNK + 1);
    for _ in 0..JUNK {
        let tag = hex::encode(rand::random::<[u8; 16]>());
        let junk = EventBuilder::new(Kind::GiftWrap, &content)
            .tags([
                Tag::public_key(channel().public_key()),
                Tag::custom(TagKind::custom(keep_approval::wrap::TAG_NAME), [tag]),
            ])
            .sign_with_keys(&keys)
            .unwrap();
        lines.push(json!({ "event": junk }).to_string() + "\n");
    }
    let freeze = phone.freeze(Scope::All, epoch);
    let freeze = phone.wrap(kind::FREEZE, &freeze, super::clock::wall_clock().unwrap());
    lines.push(json!({ "event": freeze }).to_string() + "\n");

    let started = std::time::Instant::now();
    let writer = tokio::spawn(async move {
        for line in lines {
            write.write_all(line.as_bytes()).await.unwrap();
        }
        write
    });
    // The freeze at the end is answered with an anchor once every junk wrap
    // before it was read and turned away.
    let anchor = line(&mut helper).await;
    let elapsed = started.elapsed();
    assert!(anchor.get("publish").is_some(), "{anchor}");
    let rate = JUNK as f64 / elapsed.as_secs_f64();
    eprintln!("the gateway turned away {JUNK} junk wraps in {elapsed:?}: {rate:.0} a second");
    drop(writer.await.unwrap());
    task.abort();
}

/// The admin connection that started a pairing stays open while the
/// operator compares the fingerprint, however long past the idle limit, so
/// the confirmation still lands; the session's expiry bounds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admin_comparing_a_fingerprint_is_not_idle() {
    let root = tempfile::tempdir().unwrap();
    let uid = me();
    let (agent_dir, admin_dir, relay_dir) = (
        socket_dir(root.path(), "agent"),
        socket_dir(root.path(), "admin"),
        socket_dir(root.path(), "relay"),
    );
    let (keep, _) = vault(root.path());
    let first = Phone::new();
    let second = Phone::new();
    let boot = FakeBoot::default();
    boot.set_wall(super::clock::wall_clock().unwrap());
    // The test's uid is the admin uid (the gateway's own uid is a stand-in).
    let settings = Settings {
        admin_uid: Some(uid),
        ..Settings::default()
    };
    let mut state = start(keep, settings, &boot, BOOT).unwrap();
    Store {
        channel: Some(Hex32(channel().public_key().to_bytes())),
        devices: vec![StoredDevice {
            transport: Hex32(first.t()),
            alg: keep_approval::sig::Alg::P256,
            approver: keep_approval::Hex33(first.a()),
            label: "Phone".into(),
            counter: 0,
        }],
        ..Store::default()
    }
    .save(state.keep_mut())
    .unwrap();
    state
        .configure_approvals(Some(channel()), vec!["wss://relay.example.com".into()], 60)
        .unwrap();
    let (agent, admin, relay_socket) = (
        agent_dir.join("agent.sock"),
        admin_dir.join("admin.sock"),
        relay_dir.join("relay.sock"),
    );
    let agent_listener = server::bind(&agent, uid).unwrap();
    let admin_listener = server::bind(&admin, uid).unwrap();
    let relay_listener = server::bind(&relay_socket, uid).unwrap();
    let idle = Duration::from_millis(300);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let gateway = tokio::spawn(server::serve(
        state,
        agent_listener,
        admin_listener,
        Some((relay_listener, uid)),
        Limits {
            admin_idle: idle,
            ..Limits::default()
        },
        async {
            let _ = stopped.await;
        },
    ));
    let (read, mut helper_write) = UnixStream::connect(&relay_socket)
        .await
        .unwrap()
        .into_split();
    let mut helper = BufReader::new(read).lines();
    assert!(line(&mut helper).await.get("relays").is_some());
    assert!(line(&mut helper).await.get("subscribe").is_some());

    // An admin connection with nothing going on is still closed when idle.
    let (read, _quiet) = UnixStream::connect(&admin).await.unwrap().into_split();
    let mut quiet = BufReader::new(read).lines();
    let closed = tokio::time::timeout(idle * 10, quiet.next_line())
        .await
        .expect("an idle admin connection is closed");
    assert!(closed.unwrap().is_none());

    let (read, mut write) = UnixStream::connect(&admin).await.unwrap().into_split();
    let mut admin_read = BufReader::new(read).lines();
    write
        .write_all(b"{\"op\":\"approver_pair\",\"label\":\"Tablet\"}\n")
        .await
        .unwrap();
    let answer = line(&mut admin_read).await;
    let uri = answer["result"]["uri"].as_str().expect("a pairing code");
    let uri = keep_approval::pairing::PairingUri::parse(uri).unwrap();
    let pair = second.pair(&uri.secret, super::clock::wall_clock().unwrap());
    helper_write
        .write_all(format!("{}\n", json!({ "event": pair })).as_bytes())
        .await
        .unwrap();
    let shown = line(&mut admin_read).await;
    assert!(shown["result"]["fingerprint"].is_string(), "{shown}");
    // The operator takes many idle periods to compare.
    tokio::time::sleep(idle * 6).await;
    write
        .write_all(b"{\"op\":\"approver_confirm\"}\n")
        .await
        .unwrap();
    let confirmed = tokio::time::timeout(Duration::from_secs(5), admin_read.next_line())
        .await
        .expect("an answer in time")
        .unwrap()
        .expect("the connection was kept");
    let confirmed: Value = serde_json::from_str(&confirmed).unwrap();
    assert!(confirmed["pending"].is_string(), "{confirmed}");

    let _ = stop.send(());
    gateway.await.unwrap().unwrap();
}
