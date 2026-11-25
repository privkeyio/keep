// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep-desktop phone <uri>`: the test approver without a window, for
//! `scripts/gateway-approvals-e2e.sh` with `KEEP_E2E_PHONE` naming this
//! binary. It prints the lines keep-mobile's `mobile_approver` example
//! does and takes its commands, with freezes for `all` only, driving the
//! same approver the Test Approver screen does.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use keep_mobile::{ApproverCallbacks, ApproverEvent};

use crate::approver_service::TestApprover;

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

struct Printer {
    requests: Arc<Mutex<VecDeque<String>>>,
}

impl Printer {
    fn requests(&self) -> std::sync::MutexGuard<'_, VecDeque<String>> {
        self.requests.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ApproverCallbacks for Printer {
    fn on_event(&self, event: ApproverEvent) {
        match event {
            ApproverEvent::Paired { .. } => say("paired"),
            ApproverEvent::PairingRefused { reason, ended, .. } => {
                say(&format!("refused {reason} ended={ended}"))
            }
            ApproverEvent::Request { request } => {
                // Queued before it is reported, so an answer to the line finds it.
                self.requests().push_back(request.request_id.clone());
                say(&format!(
                    "request {} \"{}\" {}",
                    request.request_id, request.op, request.reason
                ));
            }
            ApproverEvent::RequestRefused { reason } => say(&format!("bad-request {reason}")),
            ApproverEvent::RequestExpired { request_id } => {
                self.requests().retain(|r| *r != request_id);
                say(&format!("lapsed {request_id}"))
            }
            ApproverEvent::Outcome {
                request_id,
                outcome,
            } => {
                self.requests().retain(|r| *r != request_id);
                say(&format!("outcome {request_id} \"{outcome}\""));
            }
            ApproverEvent::Anchor {
                epoch,
                all_frozen,
                audit_seq,
                ..
            } => say(&format!("anchor {epoch} {all_frozen} {audit_seq}")),
            ApproverEvent::Alert { message, .. } => say(&format!("alert {message}")),
        }
    }
}

pub fn run(uri: &str) -> ! {
    let approver = TestApprover::new().unwrap_or_else(|e| {
        eprintln!("the test approver could not start: {e}");
        std::process::exit(1)
    });
    let requests = Arc::new(Mutex::new(VecDeque::new()));
    let printer = Arc::new(Printer {
        requests: requests.clone(),
    });
    match approver.pair_with(uri, printer.clone()) {
        Ok(fingerprint) => say(&format!("fingerprint {fingerprint}")),
        Err(e) => {
            eprintln!("pairing: {e}");
            std::process::exit(1)
        }
    }

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let mut words = line.split_whitespace();
        let outcome = match (words.next(), words.next()) {
            (Some(verdict @ ("approve" | "deny")), None) => {
                let Some(id) = printer.requests().front().cloned() else {
                    say("no-request");
                    continue;
                };
                let sent = if verdict == "approve" {
                    approver.approve(&id)
                } else {
                    approver.deny(&id)
                };
                // A send that failed leaves the request waiting, to decide
                // again. One that is no longer waiting is dropped.
                if sent.is_ok() || !approver.is_waiting(&id) {
                    printer.requests().retain(|r| *r != id);
                }
                sent
            }
            (Some("freeze"), Some("all")) => approver.freeze_all(),
            (Some("unfreeze"), Some("all")) => approver.unfreeze_all(),
            (Some("quit"), None) => std::process::exit(0),
            _ => {
                say("bad-command");
                continue;
            }
        };
        if let Err(e) = outcome {
            say(&format!("send-failed {e}"));
        }
    }
    // Without commands (stdin ended) it goes on reporting until killed.
    loop {
        std::thread::park();
    }
}
