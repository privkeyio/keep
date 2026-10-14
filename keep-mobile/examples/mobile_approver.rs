// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! keep-mobile's approver as a stand-in phone for the approvals end-to-end
//! test, `scripts/gateway-approvals-e2e.sh`, with `KEEP_E2E_PHONE` naming
//! this binary. Not for real use: the phone decides whatever it is told to,
//! and its approver key is a software P-256 key that signs as Android's
//! Keystore does (DER, `s` left as it comes).
//!
//! ```text
//! mobile_approver phone <uri>   pair with the pairing code <uri>, then
//!                               follow commands on stdin
//! ```
//!
//! It takes and prints the lines `approval_peer phone` does: commands
//! `approve`, `deny`, `freeze all|<credential id>`, `unfreeze all|<id>`,
//! `quit`; reports `fingerprint <fp>`, `paired`, `refused <reason>`,
//! `request <id> "<op>" <reason>`, `bad-request <reason>`, `outcome <id>
//! "<outcome>"`, `anchor <epoch> <all frozen> <audit seq>`, and `alert
//! <message>`.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use keep_mobile::{
    ApproverCallbacks, ApproverEvent, ApproverHandler, KeepMobile, KeepMobileError, SecureStorage,
    ShareMetadataInfo,
};
use p256::ecdsa::signature::Signer;

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

#[derive(Default)]
struct Memory(Mutex<HashMap<String, Vec<u8>>>);

impl SecureStorage for Memory {
    fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
        Err(KeepMobileError::StorageNotFound)
    }
    fn has_share(&self) -> bool {
        false
    }
    fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
        None
    }
    fn delete_share(&self) -> Result<(), KeepMobileError> {
        Ok(())
    }
    fn store_share_by_key(
        &self,
        key: String,
        data: Vec<u8>,
        _: ShareMetadataInfo,
    ) -> Result<(), KeepMobileError> {
        self.0.lock().unwrap().insert(key, data);
        Ok(())
    }
    fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
        self.0
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(KeepMobileError::StorageNotFound)
    }
    fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
        Vec::new()
    }
    fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
    fn get_active_share_key(&self) -> Option<String> {
        None
    }
    fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
        Ok(())
    }
}

/// A software approver key that signs as the Keystore does: SHA-256 over
/// the digest, DER, and `s` high every other time.
struct Keystore {
    key: p256::ecdsa::SigningKey,
    flip: Mutex<bool>,
}

impl Keystore {
    fn public(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn sign(&self, digest: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = self.key.sign(digest);
        let mut flip = self.flip.lock().unwrap();
        *flip = !*flip;
        let sig = if *flip {
            let (r, s) = sig.split_scalars();
            p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap()
        } else {
            sig
        };
        sig.to_der().as_bytes().to_vec()
    }
}

struct Printer {
    requests: Arc<Mutex<VecDeque<String>>>,
}

impl ApproverCallbacks for Printer {
    fn on_event(&self, event: ApproverEvent) {
        match event {
            ApproverEvent::Paired { .. } => say("paired"),
            ApproverEvent::PairingRefused { reason } => say(&format!("refused {reason}")),
            ApproverEvent::Request { request } => {
                say(&format!(
                    "request {} \"{}\" {}",
                    request.request_id, request.op, request.reason
                ));
                self.requests.lock().unwrap().push_back(request.request_id);
            }
            ApproverEvent::RequestRefused { reason } => say(&format!("bad-request {reason}")),
            ApproverEvent::Outcome {
                request_id,
                outcome,
            } => {
                self.requests.lock().unwrap().retain(|r| *r != request_id);
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

fn scope(word: &str) -> Option<String> {
    (word != "all").then(|| word.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some("phone"), Some(uri)) = (args.get(1).map(String::as_str), args.get(2)) else {
        eprintln!("usage: mobile_approver phone <uri>");
        std::process::exit(2);
    };
    // Warnings only, on stderr: keep-mobile logs everything otherwise, and
    // stdout carries the reports.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
    let mobile = Arc::new(KeepMobile::new(Arc::new(Memory::default())).expect("keep-mobile"));
    let approver = ApproverHandler::new(mobile).expect("an approver");
    let seed = keep_core::entropy::try_random_bytes::<32>().expect("entropy");
    let keystore = Keystore {
        key: p256::ecdsa::SigningKey::from_slice(&seed).expect("a P-256 key"),
        flip: Mutex::new(false),
    };
    let requests = Arc::new(Mutex::new(VecDeque::new()));
    let start = approver
        .begin_pairing(uri.clone(), keystore.public(), "e2e phone".into())
        .expect("a pairing");
    say(&format!("fingerprint {}", start.fingerprint));
    approver
        .clone()
        .finish_pairing(
            keystore.sign(&start.digest),
            Arc::new(Printer {
                requests: requests.clone(),
            }),
        )
        .expect("the pairing sent");

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let mut words = line.split_whitespace();
        let outcome = match (words.next(), words.next()) {
            (Some(verdict @ ("approve" | "deny")), None) => {
                let Some(id) = requests.lock().unwrap().pop_front() else {
                    say("no-request");
                    continue;
                };
                let approve = verdict == "approve";
                approver
                    .decision_digest(id.clone(), approve)
                    .and_then(|digest| approver.send_decision(id, approve, keystore.sign(&digest)))
            }
            (Some("freeze"), Some(word)) => approver.freeze(scope(word)),
            (Some("unfreeze"), Some(word)) => approver
                .unfreeze_digest(scope(word))
                .and_then(|digest| approver.send_unfreeze(scope(word), keystore.sign(&digest))),
            (Some("quit"), None) => break,
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
    std::thread::park();
}
