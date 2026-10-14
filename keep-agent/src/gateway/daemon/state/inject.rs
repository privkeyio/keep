// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `http_request`, the gateway's side: a request is checked against the
//! secret's rules, recorded, and registered as in flight under the state
//! lock; a task outside the lock hands it to a fresh inject worker and
//! brings back the response, which is checked again here before the agent
//! sees it. A freeze, revoke or disconnect answers the agent at once and
//! drops the worker's connection, which stops the worker.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::{tool_result, Pending, Refusal, Reply, State};
use crate::gateway::audit::RefusalKind;
use crate::gateway::GrantedCredential;
use crate::inject::rule::{self, HttpAsk, HTTP_KINDS};
use crate::inject::wire::{Cause, WorkerRequest, MAX_REQUEST_LINE};
use crate::policy::secret_entry;
use crate::scope::Operation;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Requests in flight at once: in all, per credential and per uid.
pub(crate) const MAX_IN_FLIGHT: usize = 4;
pub(crate) const MAX_PER_CREDENTIAL: usize = 1;
pub(crate) const MAX_PER_UID: usize = 2;

/// Where the gateway reaches inject workers: a socket systemd listens on and
/// starts one worker per connection behind. Its directory and the peer must
/// be `owner`'s, root in production.
#[derive(Debug, Clone)]
pub struct InjectSettings {
    pub socket: PathBuf,
    pub owner: u32,
}

/// One request handed to the task that talks to a worker.
pub(crate) struct InjectJob {
    pub id: [u8; 32],
    /// The request line for the worker, the secret inside it.
    pub line: Zeroizing<Vec<u8>>,
    /// The secret alone, for checking the response again.
    pub secret: Zeroizing<Vec<u8>>,
    /// Resolves (or fails) when the request is withdrawn.
    pub cancel: oneshot::Receiver<()>,
}

/// What became of a request handed to a worker.
pub(crate) enum InjectOutcome {
    /// The response, already checked again, as the agent will see it.
    Answer(Value),
    Failed(Cause),
}

struct InFlight {
    credential: [u8; 16],
    uid: u32,
    rpc_id: Value,
    reply: oneshot::Sender<Zeroizing<String>>,
    /// Dropped to withdraw the request from its task.
    _cancel: oneshot::Sender<()>,
}

#[derive(Default)]
pub(crate) struct Injects {
    /// Set when `http_request` is served.
    jobs: Option<mpsc::Sender<InjectJob>>,
    /// The other end, and where workers are reached, for the server's task.
    receiver: Option<(mpsc::Receiver<InjectJob>, InjectSettings)>,
    inflight: HashMap<[u8; 32], InFlight>,
}

impl Injects {
    pub(crate) fn new(settings: Option<InjectSettings>) -> Self {
        let (jobs, receiver) = settings
            .map(|settings| {
                let (tx, rx) = mpsc::channel(MAX_IN_FLIGHT * 2);
                (tx, (rx, settings))
            })
            .unzip();
        Self {
            jobs,
            receiver,
            ..Self::default()
        }
    }
}

/// `request` as one line, written into a buffer sized for the longest a
/// worker takes, so it never grows and leaves a copy of the secret behind.
fn request_line(request: &WorkerRequest) -> Option<Zeroizing<Vec<u8>>> {
    struct Bounded<'a>(&'a mut Vec<u8>);
    impl std::io::Write for Bounded<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Room is kept for the newline.
            if self.0.len() + buf.len() >= MAX_REQUEST_LINE {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_LINE));
    serde_json::to_writer(Bounded(&mut line), request).ok()?;
    line.push(b'\n');
    Some(line)
}

fn failed(cause: Cause) -> Refusal {
    Refusal::Policy {
        kind: RefusalKind::Failed,
        message: cause.message().into(),
        detail: cause.message().into(),
    }
}

/// A policy refusal. Every one reads the same to the agent, so it learns
/// nothing about the secret (its length, its bytes) or the rules beyond what
/// `list_secrets` shows; the reason goes to the audit log.
fn refused(reason: impl std::fmt::Display) -> Refusal {
    Refusal::Policy {
        kind: RefusalKind::Denied,
        message: "denied: request not allowed".into(),
        detail: format!("denied: {reason}"),
    }
}

/// The reason a rule check gave, for the audit log.
fn reason(e: crate::error::AgentError) -> Refusal {
    match e {
        crate::error::AgentError::ScopeViolation(m) => refused(m),
        other => refused(other),
    }
}

/// The first 128 bits of `data`'s SHA-256, in hex: enough to tell requests
/// apart in the audit log, short enough that its entry still holds the path.
fn hex_sha256(data: &[u8]) -> String {
    hex::encode(&keep_approval::sha256(data)[..16])
}

impl State {
    /// The worker connections the task outside the lock serves, taken once
    /// by the server.
    pub(crate) fn take_inject_jobs(
        &mut self,
    ) -> Option<(mpsc::Receiver<InjectJob>, InjectSettings)> {
        self.injects.receiver.take()
    }

    /// Handle `http_request`: answered now when refused, later otherwise.
    pub(super) fn http_request(
        &mut self,
        granted: &GrantedCredential,
        rpc_id: Value,
        args: &Value,
        now: u64,
    ) -> Reply {
        match self.start_request(granted, rpc_id.clone(), args, now) {
            Ok(pending) => Reply::Later(pending),
            Err(refusal) => Reply::Now(self.answer_tool(
                granted,
                rpc_id,
                crate::gateway::daemon::tools::HTTP_REQUEST,
                Err(refusal),
                now,
            )),
        }
    }

    fn start_request(
        &mut self,
        granted: &GrantedCredential,
        rpc_id: Value,
        args: &Value,
        now: u64,
    ) -> std::result::Result<Pending, Refusal> {
        super::only_args(args, &["secret", "method", "url", "headers", "body"])?;
        let text = |name: &str, required: bool| -> std::result::Result<String, Refusal> {
            match args.get(name) {
                Some(Value::String(s)) => Ok(s.clone()),
                None | Some(Value::Null) if !required => Ok(String::new()),
                _ => Err(Refusal::params(format!("{name} must be a string"))),
            }
        };
        let secret_hex = text("secret", true)?;
        let method = text("method", true)?;
        let url = text("url", true)?;
        let body = text("body", false)?;
        let headers: Vec<(String, String)> = match args.get("headers") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| match v {
                    Value::String(v) => Ok((k.clone(), v.clone())),
                    _ => Err(Refusal::params("header values must be strings")),
                })
                .collect::<std::result::Result<_, _>>()?,
            Some(_) => return Err(Refusal::params("headers must be an object")),
        };
        let secret = super::parse_secret_id(&secret_hex)
            .ok_or_else(|| Refusal::params("secret must be a secret id, 64 lowercase hex"))?;
        let entry =
            secret_entry(&granted.grant, Operation::HttpRequest, &secret).map_err(refused)?;
        let checked = rule::check_request(
            entry,
            &HttpAsk {
                method: &method,
                url: &url,
                headers: &headers,
                body: &body,
            },
        )
        .map_err(reason)?;
        if self.injects.jobs.is_none() {
            return Err(failed(Cause::Unavailable));
        }
        let uid = granted.credential.uid;
        let credential = granted.credential.id;
        let flying = &self.injects.inflight;
        if flying.len() >= MAX_IN_FLIGHT
            || flying
                .values()
                .filter(|f| f.credential == credential)
                .count()
                >= MAX_PER_CREDENTIAL
            || flying.values().filter(|f| f.uid == uid).count() >= MAX_PER_UID
        {
            return Err(failed(Cause::Busy));
        }
        let value = self
            .keep
            .use_secret(&secret, &HTTP_KINDS)
            .map_err(|_| refused("that secret cannot be used"))?;
        let header = checked.rule.header_value(&value).map_err(reason)?;
        let mut sent: Vec<[String; 2]> = headers
            .iter()
            .map(|(n, v)| [n.to_ascii_lowercase(), v.clone()])
            .collect();
        sent.push([
            checked.rule.header.clone(),
            String::from_utf8(header.to_vec())
                .map_err(|_| refused("that secret cannot be used"))?,
        ]);
        sent.push(["accept-encoding".into(), "identity".into()]);
        let request = WorkerRequest {
            method: checked.method.as_str().into(),
            url: checked.url.as_str().into(),
            headers: sent,
            body_b64: B64.encode(body.as_bytes()),
            secret_b64: B64.encode(&*value),
        };
        // A worker refuses a longer line, after the secret has left.
        let line =
            request_line(&request).ok_or_else(|| refused("the request is too large to send"))?;
        drop(request);
        // What the agent wrote comes last: the audit log caps what an entry
        // holds, and a long path must not cut off the secret or the hashes.
        let detail = format!(
            "secret {} url sha256 {} body sha256 {} {} {}:{}{}",
            hex::encode(&secret[..16]),
            hex_sha256(checked.url.as_str().as_bytes()),
            hex_sha256(body.as_bytes()),
            checked.method.as_str(),
            checked.host(),
            checked.port(),
            checked.url.path(),
        );
        // Only this lock's holder sends, so room seen here is still there.
        if self.injects.jobs.as_ref().is_none_or(|s| s.capacity() == 0) {
            return Err(failed(Cause::Busy));
        }
        // Recorded before the secret leaves the gateway; not sent if it
        // cannot be.
        self.served(
            granted,
            crate::gateway::daemon::tools::HTTP_REQUEST,
            &detail,
            now,
        )?;
        let id: [u8; 32] =
            keep_core::entropy::try_random_bytes().map_err(|e| Refusal::Internal(e.to_string()))?;
        let (reply_tx, reply_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let job = InjectJob {
            id,
            line,
            secret: Zeroizing::new(value.to_vec()),
            cancel: cancel_rx,
        };
        let sent = self.injects.jobs.as_ref().map(|s| s.try_send(job));
        if !matches!(sent, Some(Ok(()))) {
            return Err(failed(Cause::Busy));
        }
        self.injects.inflight.insert(
            id,
            InFlight {
                credential,
                uid,
                rpc_id,
                reply: reply_tx,
                _cancel: cancel_tx,
            },
        );
        Ok(Pending {
            request_id: Some(id),
            reply: reply_rx,
        })
    }

    /// Answer request `id` with what its worker brought back, unless it was
    /// withdrawn meanwhile. A response that carried the secret freezes the
    /// credential: an endpoint that reflects what the agent sends would
    /// otherwise answer guesses at the secret, one bit each.
    pub(crate) fn finish_inject(&mut self, id: [u8; 32], outcome: InjectOutcome) {
        let Some(flight) = self.injects.inflight.remove(&id) else {
            return;
        };
        let line = match outcome {
            InjectOutcome::Answer(content) => tool_result(flight.rpc_id, &content, false),
            InjectOutcome::Failed(cause) => {
                if cause == Cause::SecretInResponse {
                    self.leaked(&flight.credential);
                }
                tool_result(flight.rpc_id, &Value::String(cause.message().into()), true)
            }
        };
        let _ = flight.reply.send(line);
    }

    fn leaked(&mut self, credential: &[u8; 16]) {
        let now = self.clock.now();
        self.record_refusal(
            credential,
            RefusalKind::Denied,
            "http_request: the response carried the secret",
            now,
        );
        let scope = keep_approval::change::Scope::Credential(keep_approval::Hex16(*credential));
        let store = self.store().ok();
        if let Err(e) = self.freeze(scope, "a response carried its secret", store) {
            tracing::error!(error = %e, "a credential whose response carried its secret could not be frozen");
        }
    }

    /// Withdraw the requests `covered` matches: their agents are told at
    /// once, and their workers' connections are dropped.
    pub(super) fn cancel_injects(&mut self, covered: impl Fn(&[u8; 16]) -> bool) {
        let withdrawn: Vec<InFlight> = self
            .injects
            .inflight
            .extract_if(|_, f| covered(&f.credential))
            .map(|(_, f)| f)
            .collect();
        for flight in withdrawn {
            let line = tool_result(
                flight.rpc_id,
                &Value::String(Cause::Canceled.message().into()),
                true,
            );
            let _ = flight.reply.send(line);
        }
    }

    /// Withdraw request `id`, whose agent's connection went away.
    pub(super) fn cancel_inject(&mut self, id: &[u8; 32]) {
        self.injects.inflight.remove(id);
    }

    #[cfg(test)]
    pub(crate) fn injects_in_flight(&self) -> usize {
        self.injects.inflight.len()
    }
}

/// The response as the agent sees it, after the gateway's own checks: no
/// encoding, only the returned headers, no copy of the secret anywhere in
/// what the worker read, and the body cut to the agent's limit.
pub(crate) fn checked_response(
    response: crate::inject::wire::WorkerResponse,
    secret: &[u8],
) -> InjectOutcome {
    use crate::inject::wire::{MAX_HEADER_VALUE, MAX_RESPONSE_BODY, RETURNED_HEADERS};
    let Ok(mut body) = B64.decode(&response.body_b64).map(Zeroizing::new) else {
        return InjectOutcome::Failed(Cause::Http);
    };
    if body.len() > MAX_RESPONSE_BODY + crate::inject::scan::longest_form(secret.len()) {
        return InjectOutcome::Failed(Cause::Http);
    }
    let mut headers = serde_json::Map::new();
    for [name, value] in &response.headers {
        let name = name.to_ascii_lowercase();
        if name == "content-encoding" && !value.eq_ignore_ascii_case("identity") {
            return InjectOutcome::Failed(Cause::EncodedResponse);
        }
        if RETURNED_HEADERS.contains(&name.as_str())
            && value.len() <= MAX_HEADER_VALUE
            && rule::is_header_value(value.as_bytes())
        {
            headers.insert(name, Value::String(value.clone()));
        }
    }
    let scanner = crate::inject::scan::Scanner::new(secret);
    if headers
        .values()
        .any(|v| scanner.found_in(v.as_str().unwrap_or_default().as_bytes()))
        || scanner.found_in(&body)
    {
        return InjectOutcome::Failed(Cause::SecretInResponse);
    }
    let truncated = response.more || body.len() > MAX_RESPONSE_BODY;
    body.truncate(MAX_RESPONSE_BODY);
    let (text, base64) = match std::str::from_utf8(&body) {
        Ok(text) => (text.to_string(), false),
        Err(e) if truncated && e.error_len().is_none() => {
            // Cut inside a character: give the whole characters before it.
            let valid = e.valid_up_to();
            (String::from_utf8_lossy(&body[..valid]).into_owned(), false)
        }
        Err(_) => (B64.encode(&*body), true),
    };
    InjectOutcome::Answer(json!({
        "status": response.status,
        "headers": headers,
        "body": text,
        "body_base64": base64,
        "truncated": truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body_b64: String) -> WorkerRequest {
        WorkerRequest {
            method: "GET".into(),
            url: "https://api.example.com/v1".into(),
            headers: vec![["authorization".into(), "Bearer abcdefghijkl".into()]],
            body_b64,
            secret_b64: "YWJjZGVmZ2hpamts".into(),
        }
    }

    #[test]
    fn a_request_line_fills_its_buffer_without_growing_it() {
        let bare = request_line(&request(String::new())).unwrap().len();
        let line = request_line(&request("A".repeat(MAX_REQUEST_LINE - bare))).unwrap();
        assert_eq!(line.len(), MAX_REQUEST_LINE);
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.capacity(), MAX_REQUEST_LINE);
        assert!(request_line(&request("A".repeat(MAX_REQUEST_LINE - bare + 1))).is_none());
    }
}
