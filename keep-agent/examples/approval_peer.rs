// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! A stand-in relay and approver phone for the approvals end-to-end test,
//! `scripts/gateway-approvals-e2e.sh`. Not for real use: the phone decides
//! whatever it is told to.
//!
//! ```text
//! approval_peer relay <port>   run a relay on 127.0.0.1:<port> until killed
//! approval_peer phone <uri>    pair with the pairing code <uri> over its
//!                              relays, then follow commands on stdin
//! ```
//!
//! The phone reads one command per line: `approve` or `deny` (the oldest
//! request not yet decided), `freeze all`, `freeze <credential id>`,
//! `unfreeze all`, `unfreeze <credential id>` (at the latest anchor's
//! epoch), or `quit`. It reports one line per event on stdout:
//! `fingerprint <fp>`, `paired`, `refused <reason>`, `request <id> <op>
//! <reason>`, `bad-request <error>`, `outcome <id> <outcome>` and
//! `anchor <epoch> <all frozen> <audit seq>`.

use std::collections::VecDeque;
use std::io::Write;

use keep_approval::binding::check_request;
use keep_approval::change::Scope;
use keep_approval::messages::{
    self as wire, Anchor, Decision, Freeze, FreezeAction, Outcome, Pairing, Request, Verdict, V1,
};
use keep_approval::pairing::PairingUri;
use keep_approval::sig;
use keep_approval::wrap::{self, Candidate, SeenWraps, TagKey};
use keep_approval::{kind, Hex16, Hex32};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client, Event, Filter, Keys, Kind, PublicKey, RelayPoolNotification};
use tokio::io::AsyncBufReadExt;

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("relay") => {
            let port: u16 = args
                .get(2)
                .and_then(|p| p.parse().ok())
                .expect("usage: approval_peer relay <port>");
            let relay = LocalRelay::new(
                RelayBuilder::default()
                    .addr([127, 0, 0, 1].into())
                    .port(port),
            );
            relay.run().await.expect("the relay starts");
            say(&format!("relay {}", relay.url().await));
            std::future::pending::<()>().await;
        }
        Some("phone") => {
            let uri = args.get(2).expect("usage: approval_peer phone <uri>");
            phone(uri).await;
        }
        _ => {
            eprintln!("usage: approval_peer relay <port> | approval_peer phone <uri>");
            std::process::exit(2);
        }
    }
}

struct Phone {
    transport: Keys,
    approver: Keys,
    channel: [u8; 32],
    seen: SeenWraps,
    counter: u64,
    epoch: u64,
    requests: VecDeque<Request>,
    client: Client,
}

impl Phone {
    fn t(&self) -> [u8; 32] {
        sig::xonly(&self.transport)
    }

    async fn send(&self, kind: u16, content: &str) {
        let tag = TagKey::for_peer(&self.transport, &self.channel).expect("a tag key");
        let event = wrap::wrap(
            &self.transport,
            &self.channel,
            &tag,
            kind,
            content,
            now(),
        )
        .expect("a wrap");
        if let Err(e) = self.client.send_event(&event).await {
            say(&format!("send-failed {e}"));
        }
    }

    fn open(&mut self, event: &Event) -> Option<(u16, String)> {
        let candidates = [Candidate {
            id: (),
            tag_key: TagKey::for_peer(&self.transport, &self.channel).ok()?,
            sender: Some(self.channel),
        }];
        wrap::open(&self.transport, event, &candidates, &mut self.seen, now())
            .ok()
            .map(|o| (o.kind, o.content))
    }

    fn received(&mut self, kind: u16, content: &str) {
        match kind {
            kind::PAIRING => match wire::parse::<Pairing>(content) {
                Ok(Pairing::Paired { frozen, .. }) => {
                    self.epoch = frozen.epoch;
                    say("paired");
                }
                Ok(Pairing::Refused { reason, .. }) => say(&format!("refused {reason}")),
                _ => say("bad-pairing"),
            },
            kind::REQUEST => {
                let request: Request = match wire::parse(content) {
                    Ok(r) => r,
                    Err(e) => return say(&format!("bad-request {e}")),
                };
                if let Err(e) = check_request(&request, &self.channel) {
                    return say(&format!("bad-request {e}"));
                }
                say(&format!(
                    "request {} {} {}",
                    request.request_id.to_hex(),
                    serde_json::to_string(&request.op).unwrap_or_default(),
                    serde_json::to_string(&request.reason).unwrap_or_default()
                ));
                self.requests.push_back(request);
            }
            kind::OUTCOME => {
                if let Ok(outcome) = wire::parse::<Outcome>(content) {
                    self.requests
                        .retain(|r| r.request_id != outcome.request_id);
                    say(&format!(
                        "outcome {} {}",
                        outcome.request_id.to_hex(),
                        serde_json::to_string(&outcome.outcome).unwrap_or_default()
                    ));
                }
            }
            kind::ANCHOR => {
                if let Ok(anchor) = wire::parse::<Anchor>(content) {
                    self.epoch = anchor.frozen.epoch;
                    say(&format!(
                        "anchor {} {} {}",
                        anchor.frozen.epoch, anchor.frozen.all, anchor.anchor.seq
                    ));
                }
            }
            other => say(&format!("message {other}")),
        }
    }

    async fn decide(&mut self, verdict: Verdict) {
        let Some(request) = self.requests.pop_front() else {
            return say("no-request");
        };
        let digest = sig::decision_digest(
            &self.channel,
            &sig::xonly(&self.approver),
            &request.request_hash.0,
            verdict,
        );
        let decision = wire::to_text(&Decision {
            v: V1,
            request_id: request.request_id,
            request_hash: request.request_hash,
            decision: verdict,
            sig: sig::sign(&self.approver, &digest),
        });
        self.send(kind::DECISION, &decision).await;
    }

    async fn freeze(&mut self, action: FreezeAction, scope: &str) {
        let scope = if scope == "all" {
            Scope::All
        } else {
            let mut id = [0u8; 16];
            if hex::decode_to_slice(scope, &mut id).is_err() {
                return say("bad-scope");
            }
            Scope::Credential(Hex16(id))
        };
        // A freeze is the transport key's, an unfreeze the approver key's.
        let signer = match action {
            FreezeAction::Freeze => self.transport.clone(),
            FreezeAction::Unfreeze => self.approver.clone(),
        };
        self.counter += 1;
        let digest = sig::freeze_digest(
            &self.channel,
            &sig::xonly(&signer),
            self.counter,
            self.epoch,
            action,
            scope,
        );
        let freeze = wire::to_text(&Freeze {
            v: V1,
            action,
            scope,
            counter: self.counter,
            epoch: self.epoch,
            signer: Hex32(sig::xonly(&signer)),
            sig: sig::sign(&signer, &digest),
        });
        self.send(kind::FREEZE, &freeze).await;
    }
}

async fn phone(uri: &str) {
    let uri = PairingUri::parse(uri).expect("a pairing code");
    let client = Client::default();
    for relay in &uri.relays {
        client.add_relay(relay).await.expect("a relay");
    }
    client.connect().await;
    client
        .wait_for_connection(std::time::Duration::from_secs(10))
        .await;
    let mut phone = Phone {
        transport: Keys::generate(),
        approver: Keys::generate(),
        channel: uri.gateway,
        seen: SeenWraps::default(),
        counter: 0,
        epoch: 0,
        requests: VecDeque::new(),
        client: client.clone(),
    };
    let (t, a) = (phone.t(), sig::xonly(&phone.approver));
    let mut events = client.notifications();
    client
        .subscribe(
            Filter::new()
                .kind(Kind::GiftWrap)
                .pubkey(PublicKey::from_slice(&t).expect("a key")),
            None,
        )
        .await
        .expect("a subscription");
    let pair = Pairing::Pair {
        v: V1,
        label: "e2e phone".into(),
        approver: Hex32(a),
        proof: sig::pair_proof(&uri.secret, &phone.channel, &t, &a),
        approver_sig: sig::sign(
            &phone.approver,
            &sig::pair_approver_digest(&phone.channel, &t, &a),
        ),
    };
    let tag = TagKey::for_pairing(&uri.secret);
    let event = wrap::wrap(
        &phone.transport,
        &phone.channel,
        &tag,
        kind::PAIRING,
        &wire::to_text(&pair),
        now(),
    )
    .expect("a pairing wrap");
    client.send_event(&event).await.expect("the pairing sent");
    say(&format!("fingerprint {}", sig::fingerprint(&t, &a)));

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Ok(Some(line)) = line else { break };
                let mut words = line.split_whitespace();
                match (words.next(), words.next()) {
                    (Some("approve"), None) => phone.decide(Verdict::Approve).await,
                    (Some("deny"), None) => phone.decide(Verdict::Deny).await,
                    (Some("freeze"), Some(scope)) => phone.freeze(FreezeAction::Freeze, scope).await,
                    (Some("unfreeze"), Some(scope)) => phone.freeze(FreezeAction::Unfreeze, scope).await,
                    (Some("quit"), None) => break,
                    _ => say("bad-command"),
                }
            }
            notification = events.recv() => {
                match notification {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if let Some((kind, content)) = phone.open(&event) {
                            phone.received(kind, &content);
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    client.shutdown().await;
}
