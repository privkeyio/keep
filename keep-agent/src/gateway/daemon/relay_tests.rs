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
    let socket = dir.join("relay.sock");
    let listener = server::bind(&socket, uid).unwrap();
    let task = tokio::spawn(super::relay::relay_task(
        listener,
        uid.wrapping_add(1),
        link,
        shared,
        stop,
    ));
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0))), "{read:?} {buf:?}");
    task.abort();
}
