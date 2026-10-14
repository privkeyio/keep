// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `http_request` through the gateway: what reaches a worker, what the
//! agent gets back, and how a freeze or a disconnect withdraws a request.

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use base64::Engine;
use keep_core::audit::AuditEventType;
use keep_core::secret::SecretKind;
use serde_json::{json, Value};

use super::server::{with_state, Shared};
use super::state::{InjectOutcome, InjectSettings, Pending, Settings};
use super::tests::{secret_entry, secrets_grant, settings, store_secret, Gw, AGENT, OTHER};
use crate::inject::wire::{Cause, WorkerRequest, MAX_RESPONSE_BODY};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const URL: &str = "https://api.example.com/v1/items";

fn inject_settings(socket: std::path::PathBuf) -> Settings {
    Settings {
        inject: Some(InjectSettings {
            socket,
            owner: rustix::process::geteuid().as_raw(),
        }),
        ..settings()
    }
}

/// A gateway serving `http_request` through `socket`, with one credential
/// granted one secret; its id and token.
fn gateway(socket: std::path::PathBuf) -> (Gw, [u8; 32], String, String) {
    let mut g = Gw::with(inject_settings(socket));
    let secret = store_secret(&mut g, "deploy token", SecretKind::ApiToken);
    let mut entry = secret_entry(json!(hex::encode(secret)), "/v1");
    entry["http"][0]["methods"] = json!(["GET", "POST"]);
    entry["http"][0]["agent_headers"] = json!(["idempotency-key"]);
    let answer = g.admin(json!({
        "op": "issue", "name": "x", "uid": AGENT, "grant": secrets_grant(vec![entry])
    }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let cid = answer["result"]["id"].as_str().unwrap().to_string();
    let token = answer["token"].as_str().unwrap().to_string();
    (g, secret, cid, token)
}

fn call(g: &mut Gw, uid: u32, token: &str, args: Value) -> super::state::Answer {
    let line = json!({
        "token": token,
        "message": {
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": "http_request", "arguments": args }
        }
    })
    .to_string();
    g.state.agent_request(uid, line.as_bytes())
}

fn ask(secret: &[u8; 32]) -> Value {
    json!({
        "secret": hex::encode(secret),
        "method": "POST",
        "url": URL,
        "headers": { "Content-Type": "application/json", "Idempotency-Key": "k1" },
        "body": "{\"a\":1}"
    })
}

/// The tool result an answer line carries, and whether it is an error.
fn result(line: &str) -> (Value, bool) {
    let v: Value = serde_json::from_str(line).unwrap();
    let r = &v["result"];
    let text = r["content"][0]["text"].as_str().unwrap();
    (
        serde_json::from_str(text).unwrap_or(Value::String(text.into())),
        r["isError"].as_bool().unwrap(),
    )
}

fn now_result(answer: super::state::Answer) -> (Value, bool) {
    assert!(answer.pending.is_none(), "answered later");
    result(&answer.line.unwrap())
}

fn later(answer: super::state::Answer) -> Pending {
    assert!(answer.line.is_none(), "{:?}", answer.line);
    answer.pending.expect("a pending answer")
}

fn reply(pending: Pending) -> (Value, bool) {
    result(&pending.reply.blocking_recv().expect("an answer"))
}

#[test]
fn a_request_reaches_the_worker_with_its_secret_after_it_is_recorded() {
    let (mut g, secret, cid, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    let pending = later(call(&mut g, AGENT, &token, ask(&secret)));
    let job = jobs.try_recv().unwrap();
    let request: WorkerRequest = serde_json::from_slice(&job.line).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, URL);
    let headers: Vec<(&str, &str)> = request
        .headers
        .iter()
        .map(|[n, v]| (n.as_str(), v.as_str()))
        .collect();
    assert!(headers.contains(&("authorization", "Bearer tk_test_0123456789")));
    assert!(headers.contains(&("accept-encoding", "identity")));
    assert!(headers.contains(&("idempotency-key", "k1")));
    assert!(headers.contains(&("content-type", "application/json")));
    assert_eq!(headers.len(), 4);
    assert_eq!(B64.decode(&request.body_b64).unwrap(), b"{\"a\":1}");
    assert_eq!(
        B64.decode(&request.secret_b64).unwrap(),
        b"tk_test_0123456789"
    );
    assert_eq!(&*job.secret, b"tk_test_0123456789");
    let served = g.reasons(AuditEventType::AgentServed);
    let entry = served
        .iter()
        .find(|r| r.contains("http_request"))
        .expect("the use is recorded");
    let sha = |d: &[u8]| hex::encode(&keep_approval::sha256(d)[..16]);
    assert_eq!(
        entry,
        &format!(
            "agent {cid} http_request \"secret {} url sha256 {} body sha256 {} POST api.example.com:443/v1/items\"",
            hex::encode(&secret[..16]),
            sha(URL.as_bytes()),
            sha(b"{\"a\":1}"),
        )
    );
    assert!(!entry.contains("tk_test_"), "never the secret");
    assert_eq!(pending.request_id, Some(job.id));

    g.state.finish_inject(
        job.id,
        InjectOutcome::Answer(json!({ "status": 201, "body": "made" })),
    );
    let (content, err) = reply(pending);
    assert!(!err);
    assert_eq!(content["status"], json!(201));
    assert_eq!(g.state.injects_in_flight(), 0);
}

#[test]
fn requests_outside_the_grant_are_denied_before_anything_is_sent() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    let cases = [
        (
            json!({ "secret": hex::encode([9u8; 32]), "method": "GET", "url": URL }),
            "not granted",
        ),
        (
            json!({ "secret": hex::encode(secret), "method": "GET", "url": "https://api.example.com/v2" }),
            "no rule",
        ),
        (
            json!({ "secret": hex::encode(secret), "method": "DELETE", "url": URL }),
            "no rule",
        ),
        (
            json!({ "secret": hex::encode(secret), "method": "GET", "url": URL, "headers": { "Authorization": "x" } }),
            "header",
        ),
        (
            json!({ "secret": hex::encode(secret), "method": "POST", "url": URL, "body": "_method=DELETE" }),
            "body",
        ),
    ];
    for (args, why) in cases {
        let (content, err) = now_result(call(&mut g, AGENT, &token, args));
        assert!(err);
        // One answer for every refusal; the reason is in the audit log.
        assert_eq!(content, json!("denied: request not allowed"));
        let refused = g.reasons(AuditEventType::AgentRefused);
        assert!(
            refused
                .iter()
                .any(|r| r.contains("http_request") && r.contains(why)),
            "{why}: {refused:?}"
        );
    }
    assert!(jobs.try_recv().is_err(), "nothing sent");
    assert!(!g
        .reasons(AuditEventType::AgentServed)
        .iter()
        .any(|r| r.contains("http_request")));
    assert!(g
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.contains("http_request")));
    let bad = call(
        &mut g,
        AGENT,
        &token,
        json!({ "secret": "ab", "method": "GET", "url": URL }),
    );
    let v: Value = serde_json::from_str(&bad.line.unwrap()).unwrap();
    assert_eq!(v["error"]["code"], json!(-32602));
}

/// The secret, the hashes and the method stay in the audit entry however
/// long a path the agent sends.
#[test]
fn a_long_path_never_pushes_the_secret_or_hashes_out_of_the_audit_entry() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let _jobs = g.state.take_inject_jobs().unwrap();
    let url = format!("{URL}/{}", "a".repeat(300));
    let _pending = later(call(
        &mut g,
        AGENT,
        &token,
        json!({ "secret": hex::encode(secret), "method": "GET", "url": url }),
    ));
    let served = g.reasons(AuditEventType::AgentServed);
    let entry = served.iter().find(|r| r.contains("http_request")).unwrap();
    let sha = |d: &[u8]| hex::encode(&keep_approval::sha256(d)[..16]);
    assert!(
        entry.contains(&format!("secret {}", hex::encode(&secret[..16]))),
        "{entry}"
    );
    assert!(
        entry.contains(&format!("url sha256 {}", sha(url.as_bytes()))),
        "{entry}"
    );
    assert!(
        entry.contains(&format!(
            "body sha256 {} GET api.example.com:443/v1/items/aaa",
            sha(b"")
        )),
        "{entry}"
    );
}

/// A request whose line a worker would refuse is refused before it is
/// recorded or sent.
#[test]
fn a_request_too_large_for_a_worker_is_refused_before_it_is_sent() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    let query = "q".repeat(400 * 1024);
    let (content, err) = now_result(call(
        &mut g,
        AGENT,
        &token,
        json!({
            "secret": hex::encode(secret), "method": "POST",
            "url": format!("{URL}?x={query}"), "body": "b".repeat(200 * 1024)
        }),
    ));
    assert!(err);
    assert_eq!(content, json!("denied: request not allowed"));
    assert!(jobs.try_recv().is_err());
    assert!(!g
        .reasons(AuditEventType::AgentServed)
        .iter()
        .any(|r| r.contains("http_request")));
}

#[test]
fn without_a_worker_socket_the_request_is_unavailable() {
    let mut g = Gw::new();
    let secret = store_secret(&mut g, "deploy token", SecretKind::ApiToken);
    let grant = secrets_grant(vec![secret_entry(json!(hex::encode(secret)), "/v1")]);
    let answer = g.admin(json!({ "op": "issue", "name": "x", "uid": AGENT, "grant": grant }));
    let token = answer["token"].as_str().unwrap().to_string();
    let args = json!({ "secret": hex::encode(secret), "method": "GET", "url": URL });
    let (content, err) = now_result(call(&mut g, AGENT, &token, args));
    assert!(err);
    assert_eq!(content, json!("unavailable"));
}

#[test]
fn one_request_per_credential_is_in_flight_at_a_time() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let _jobs = g.state.take_inject_jobs().unwrap();
    let _first = later(call(&mut g, AGENT, &token, ask(&secret)));
    let (content, err) = now_result(call(&mut g, AGENT, &token, ask(&secret)));
    assert!(err);
    assert_eq!(content, json!("busy"));
    assert_eq!(g.state.injects_in_flight(), 1);
}

#[test]
fn a_freeze_or_revoke_answers_at_once_and_withdraws_the_request() {
    let (mut g, secret, cid, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    let pending = later(call(&mut g, AGENT, &token, ask(&secret)));
    let mut job = jobs.try_recv().unwrap();
    g.admin_ok(json!({ "op": "freeze", "id": cid }));
    assert_eq!(reply(pending), (json!("canceled"), true));
    assert!(job.cancel.try_recv().is_err(), "the task is told to stop");
    // What the worker brings back afterwards goes nowhere.
    g.state
        .finish_inject(job.id, InjectOutcome::Answer(json!({ "status": 200 })));
    assert_eq!(g.state.injects_in_flight(), 0);

    g.admin_ok(json!({ "op": "unfreeze", "id": cid }));
    let pending = later(call(&mut g, AGENT, &token, ask(&secret)));
    let _job = jobs.try_recv().unwrap();
    g.admin_ok(json!({ "op": "revoke", "id": cid }));
    assert_eq!(reply(pending), (json!("canceled"), true));
}

#[test]
fn a_disconnect_withdraws_the_request_silently() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    let pending = later(call(&mut g, AGENT, &token, ask(&secret)));
    let mut job = jobs.try_recv().unwrap();
    g.state.cancel_parked(pending.request_id.unwrap());
    assert!(job.cancel.try_recv().is_err());
    assert_eq!(g.state.injects_in_flight(), 0);
    assert!(pending.reply.blocking_recv().is_err(), "no one to answer");
}

#[test]
fn responses_carrying_the_secret_are_recorded_and_three_freeze_the_credential() {
    let (mut g, secret, cid, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    for n in 1..=3 {
        let pending = later(call(&mut g, AGENT, &token, ask(&secret)));
        let job = jobs.try_recv().unwrap();
        g.state
            .finish_inject(job.id, InjectOutcome::Failed(Cause::SecretInResponse));
        assert_eq!(reply(pending), (json!("secret in response"), true));
        let frozen = g.admin_ok(json!({ "op": "list" }))[0]["frozen"].clone();
        assert_eq!(frozen, json!(n == 3), "after {n}");
    }
    let leaks = g
        .reasons(AuditEventType::AgentRefused)
        .into_iter()
        .filter(|r| r.contains("carried the secret"))
        .count();
    // Identical refusals within a minute collapse into one entry, counted.
    assert_eq!(leaks, 1);
    let _ = cid;
}

fn leak(
    g: &mut Gw,
    jobs: &mut tokio::sync::mpsc::Receiver<super::state::InjectJob>,
    token: &str,
    secret: &[u8; 32],
) {
    let pending = later(call(g, AGENT, token, ask(secret)));
    let job = jobs.try_recv().unwrap();
    g.state
        .finish_inject(job.id, InjectOutcome::Failed(Cause::SecretInResponse));
    let _ = reply(pending);
}

fn frozen(g: &mut Gw) -> bool {
    g.admin_ok(json!({ "op": "list" }))[0]["frozen"] == json!(true)
}

#[test]
fn an_unfreeze_starts_the_leak_count_again() {
    let (mut g, secret, cid, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    leak(&mut g, &mut jobs, &token, &secret);
    leak(&mut g, &mut jobs, &token, &secret);
    g.admin_ok(json!({ "op": "freeze", "id": cid }));
    g.admin_ok(json!({ "op": "unfreeze", "id": cid }));
    leak(&mut g, &mut jobs, &token, &secret);
    assert!(!frozen(&mut g), "two before the unfreeze no longer count");
}

#[test]
fn leaks_older_than_a_day_no_longer_count() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    leak(&mut g, &mut jobs, &token, &secret);
    leak(&mut g, &mut jobs, &token, &secret);
    g.boot.advance(24 * 60 * 60 + 1);
    leak(&mut g, &mut jobs, &token, &secret);
    assert!(!frozen(&mut g));
    leak(&mut g, &mut jobs, &token, &secret);
    leak(&mut g, &mut jobs, &token, &secret);
    assert!(frozen(&mut g), "three within the day");
}

/// Another credential granted the same secret, bound to `uid`; its token.
fn another(g: &mut Gw, secret: &[u8; 32], uid: u32) -> String {
    let grant = secrets_grant(vec![secret_entry(json!(hex::encode(secret)), "/v1")]);
    let answer = g.admin(json!({ "op": "issue", "name": "more", "uid": uid, "grant": grant }));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    answer["token"].as_str().unwrap().to_string()
}

fn get(secret: &[u8; 32]) -> Value {
    json!({ "secret": hex::encode(secret), "method": "GET", "url": URL })
}

#[test]
fn in_flight_requests_are_capped_per_uid_and_in_all() {
    const THIRD: u32 = 1002;
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let _jobs = g.state.take_inject_jobs().unwrap();
    let mut held = vec![later(call(&mut g, AGENT, &token, get(&secret)))];
    let a2 = another(&mut g, &secret, AGENT);
    held.push(later(call(&mut g, AGENT, &a2, get(&secret))));
    let a3 = another(&mut g, &secret, AGENT);
    assert_eq!(
        now_result(call(&mut g, AGENT, &a3, get(&secret))),
        (json!("busy"), true),
        "two per uid"
    );
    for _ in 0..2 {
        let t = another(&mut g, &secret, OTHER);
        held.push(later(call(&mut g, OTHER, &t, get(&secret))));
    }
    let t = another(&mut g, &secret, THIRD);
    assert_eq!(
        now_result(call(&mut g, THIRD, &t, get(&secret))),
        (json!("busy"), true),
        "four in all"
    );
    assert_eq!(g.state.injects_in_flight(), 4);
}

/// A full queue to the workers refuses before anything is recorded.
#[test]
fn a_full_queue_is_busy_before_anything_is_recorded() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    for _ in 0..super::state::MAX_IN_FLIGHT * 2 {
        let pending = later(call(&mut g, AGENT, &token, get(&secret)));
        g.state.finish_inject(
            pending.request_id.unwrap(),
            InjectOutcome::Failed(Cause::Timeout),
        );
    }
    let served = g.reasons(AuditEventType::AgentServed).len();
    assert_eq!(
        now_result(call(&mut g, AGENT, &token, get(&secret))),
        (json!("busy"), true)
    );
    assert_eq!(g.reasons(AuditEventType::AgentServed).len(), served);
    assert!(jobs.try_recv().is_ok());
}

#[test]
fn a_use_that_cannot_be_recorded_is_never_sent() {
    let (mut g, secret, _, token) = gateway("/nonexistent/worker.sock".into());
    let (mut jobs, _) = g.state.take_inject_jobs().unwrap();
    g.break_log(true);
    let answer = call(&mut g, AGENT, &token, get(&secret));
    g.break_log(false);
    assert!(answer.pending.is_none());
    assert!(jobs.try_recv().is_err(), "nothing sent");
    assert_eq!(g.state.injects_in_flight(), 0);
}

#[test]
fn no_credential_is_bound_to_a_dynamic_uid_while_injection_is_on() {
    let (mut g, secret, _, _) = gateway("/nonexistent/worker.sock".into());
    let grant = secrets_grant(vec![secret_entry(json!(hex::encode(secret)), "/v1")]);
    let answer = g.admin(json!({ "op": "issue", "name": "dyn", "uid": 61_200, "grant": grant }));
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("dynamic"),
        "{answer}"
    );
    let mut plain = Gw::new();
    let answer = plain.admin(json!({
        "op": "issue", "name": "dyn", "uid": 61_200,
        "grant": super::tests::nostr_grant(plain.key)
    }));
    assert_eq!(answer["ok"], json!(true), "without injection: {answer}");
}

#[test]
fn an_answer_larger_than_a_worker_may_read_is_refused() {
    let secret = b"tk_test_0123456789";
    let limit = MAX_RESPONSE_BODY + crate::inject::scan::longest_form(secret.len());
    let answer = |len: usize| crate::inject::wire::WorkerResponse {
        status: 200,
        headers: vec![],
        body_b64: B64.encode(vec![b'a'; len]),
        more: true,
    };
    assert!(matches!(
        super::state::checked_response(answer(limit + 1), secret),
        InjectOutcome::Failed(Cause::Http)
    ));
    assert!(matches!(
        super::state::checked_response(answer(limit), secret),
        InjectOutcome::Answer(_)
    ));
}

/// A fake worker on a socket in a closed directory: answers each
/// connection with the next of `answers`, and records each request and
/// whether the gateway closed the connection afterwards.
struct FakeWorker {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    seen: Arc<Mutex<Vec<(String, bool)>>>,
    received: Arc<std::sync::atomic::AtomicUsize>,
}

fn fake_worker(answers: Vec<Option<String>>) -> FakeWorker {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("worker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = received.clone();
    std::thread::spawn(move || {
        for answer in answers {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stream = stream;
            match answer {
                Some(a) => {
                    stream.write_all(a.as_bytes()).unwrap();
                    stream.write_all(b"\n").unwrap();
                    log.lock().unwrap().push((line, false));
                }
                None => {
                    // Hold the connection until the gateway closes it.
                    let mut rest = String::new();
                    let closed = reader.read_line(&mut rest).map(|n| n == 0).unwrap_or(true);
                    log.lock().unwrap().push((line, closed));
                }
            }
        }
    });
    FakeWorker {
        _dir: dir,
        socket,
        seen,
        received,
    }
}

/// A gateway with its inject task running, as the server runs it.
struct Running {
    shared: Shared,
    stop: tokio::sync::watch::Sender<bool>,
    secret: [u8; 32],
    cid: String,
    token: String,
    rt: tokio::runtime::Runtime,
    _vault: tempfile::TempDir,
}

fn running(socket: std::path::PathBuf) -> Running {
    let (mut g, secret, cid, token) = gateway(socket);
    let (jobs, settings) = g.state.take_inject_jobs().unwrap();
    let Gw { dir, state, .. } = g;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let shared: Shared = Arc::new(Mutex::new(state));
    let (stop, _) = tokio::sync::watch::channel(false);
    rt.spawn(super::inject::inject_task(
        jobs,
        settings,
        shared.clone(),
        stop.clone(),
    ));
    Running {
        shared,
        stop,
        secret,
        cid,
        token,
        rt,
        _vault: dir,
    }
}

fn shared_call(shared: &Shared, token: &str, args: Value) -> super::state::Answer {
    let line = json!({
        "token": token,
        "message": {
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": "http_request", "arguments": args }
        }
    })
    .to_string();
    shared.lock().unwrap().agent_request(AGENT, line.as_bytes())
}

fn response_line(status: u16, headers: Value, body: &[u8], more: bool) -> String {
    json!({ "status": status, "headers": headers, "body_b64": B64.encode(body), "more": more })
        .to_string()
}

#[test]
fn a_worker_answer_is_checked_again_before_the_agent_sees_it() {
    let secret_text: &[u8] = b"tk_test_0123456789";
    let mut long = vec![b'a'; MAX_RESPONSE_BODY + 50];
    long[MAX_RESPONSE_BODY - 1..MAX_RESPONSE_BODY + 2].copy_from_slice("€".as_bytes());
    let answers = vec![
        Some(response_line(
            200,
            json!([
                ["content-type", "text/plain"],
                ["set-cookie", "s=1"],
                ["x-other", "y"]
            ]),
            b"hello",
            false,
        )),
        Some(response_line(
            200,
            json!([]),
            &[b"echo: ".as_slice(), secret_text].concat(),
            false,
        )),
        Some(response_line(
            200,
            json!([["location", "https://x.example/?t=tk_test_0123456789"]]),
            b"",
            false,
        )),
        Some(response_line(
            200,
            json!([["content-encoding", "gzip"]]),
            b"",
            false,
        )),
        Some(response_line(200, json!([]), &long, true)),
        Some(response_line(200, json!([]), &[0xff, 0xfe, 0x00], false)),
        Some(r#"{"error":"tls"}"#.into()),
        Some("not json".into()),
    ];
    let worker = fake_worker(answers);
    let r = running(worker.socket.clone());
    let mut results = Vec::new();
    for _ in 0..8 {
        let pending = later(shared_call(&r.shared, &r.token, ask(&r.secret)));
        results.push(reply(pending));
    }
    assert!(!results[0].1);
    assert_eq!(
        results[0].0["headers"],
        json!({ "content-type": "text/plain" })
    );
    assert_eq!(results[0].0["body"], json!("hello"));
    assert_eq!(results[0].0["truncated"], json!(false));
    assert_eq!(results[1], (json!("secret in response"), true));
    assert_eq!(results[2], (json!("secret in response"), true));
    assert_eq!(results[3], (json!("encoded response"), true));
    assert_eq!(results[4].0["truncated"], json!(true));
    let body = results[4].0["body"].as_str().unwrap();
    assert_eq!(
        body.len(),
        MAX_RESPONSE_BODY - 1,
        "cut before the split character"
    );
    assert_eq!(results[5].0["body_base64"], json!(true));
    assert_eq!(results[5].0["body"], json!(B64.encode([0xff, 0xfe, 0x00])));
    assert_eq!(results[6], (json!("tls"), true));
    assert_eq!(results[7], (json!("http"), true));
    let seen = worker.seen.lock().unwrap();
    assert_eq!(seen.len(), 8);
    assert!(seen[0].0.contains("\"authorization\""));
}

#[test]
fn a_freeze_closes_the_worker_connection_and_answers_the_agent() {
    let worker = fake_worker(vec![None]);
    let r = running(worker.socket.clone());
    let pending = later(shared_call(&r.shared, &r.token, ask(&r.secret)));
    for _ in 0..500 {
        if worker.received.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(worker.received.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cid = r.cid.clone();
    r.rt.block_on(with_state(&r.shared, &r.stop, move |s| {
        s.admin_request(json!({ "op": "freeze", "id": cid }).to_string().as_bytes())
    }));
    assert_eq!(reply(pending), (json!("canceled"), true));
    for _ in 0..500 {
        if !worker.seen.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let seen = worker.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].1, "the worker saw its connection closed");
}

#[test]
fn a_missing_worker_socket_or_one_owned_by_another_user_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let open = dir.path().join("worker.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&open).unwrap();
    for socket in [open, "/nonexistent/worker.sock".into()] {
        let r = running(socket);
        let pending = later(shared_call(&r.shared, &r.token, ask(&r.secret)));
        assert_eq!(reply(pending), (json!("unavailable"), true));
    }
}
