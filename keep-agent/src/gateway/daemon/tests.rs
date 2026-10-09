// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The gateway's decisions, driven through the same entry points the sockets
//! use: one request line in, one answer out.

use std::path::PathBuf;

use keep_bitcoin::bitcoin;
use keep_core::audit::{AuditEntry, AuditEventType};
use keep_core::Keep;
use serde_json::{json, Value};

use super::clock::tests::FakeBoot;
use super::clock::{Heartbeat, HEARTBEAT_KEY};
use super::state::{wallet_key, Host, Settings, State, REFUSED_CODE};
use crate::policy::{BitcoinGrant, Grant, RequestLimits};
use crate::scope::Operation;

const T0: u64 = 1_800_000_000;
const AGENT: u32 = 1000;
const OTHER: u32 = 1001;
const ADMIN: u32 = 1500;
const HOST: Host = Host {
    euid: 900,
    overflow_uid: 65_534,
    vault_owner: 901,
};
const BOOT: &str = "0f0e8c49-7d0d-4d47-a4b1-ad1b6c1b0a51";
const REBOOT: &str = "2f0e8c49-7d0d-4d47-a4b1-ad1b6c1b0a51";
const SECRET: [u8; 32] = [7; 32];
const NETWORK: keep_bitcoin::Network = keep_bitcoin::Network::Testnet;

fn settings() -> Settings {
    Settings {
        admin_uid: Some(ADMIN),
        wallet_budget_sats: 100_000,
        ..Settings::default()
    }
}

struct Gw {
    dir: tempfile::TempDir,
    boot: FakeBoot,
    state: State,
    key: [u8; 32],
}

fn vault(dir: &std::path::Path) -> (Keep, [u8; 32]) {
    let path = dir.join("keep");
    if !path.exists() {
        keep_core::storage::Storage::create(
            &path,
            "testpass",
            keep_core::crypto::Argon2Params::TESTING,
        )
        .unwrap();
    }
    let mut keep = Keep::open(&path).unwrap();
    keep.unlock("testpass").unwrap();
    let key = match keep.keyring().get_by_name("agent key") {
        Some(slot) => slot.pubkey,
        None => keep
            .import_secret_bytes(&mut SECRET.clone(), "agent key")
            .unwrap(),
    };
    (keep, key)
}

/// Start a gateway whose clocks read `boot` (boot time and wall clock).
fn start(
    keep: Keep,
    settings: Settings,
    boot: &FakeBoot,
    boot_id: &str,
) -> crate::error::Result<State> {
    State::start(keep, settings, HOST, Box::new(boot.clone()), boot_id.into())
}

impl Gw {
    fn new() -> Self {
        Self::with(settings())
    }

    fn with(settings: Settings) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (keep, key) = vault(dir.path());
        let boot = FakeBoot::default();
        boot.advance(10_000);
        boot.set_wall(T0);
        let state = start(keep, settings, &boot, BOOT).unwrap();
        Self {
            dir,
            boot,
            state,
            key,
        }
    }

    /// Stop this gateway and start another on the same vault, in boot
    /// `boot_id` with the wall clock at `wall`.
    fn restart(self, boot_id: &str, wall: u64) -> crate::error::Result<Gw> {
        let Gw {
            dir,
            boot,
            mut state,
            key,
        } = self;
        state.shut_down();
        drop(state);
        let (keep, _) = vault(dir.path());
        boot.set_wall(wall);
        let state = start(keep, settings(), &boot, boot_id)?;
        Ok(Gw {
            dir,
            boot,
            state,
            key,
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("keep")
    }

    fn admin(&mut self, request: Value) -> Value {
        let answer = self.state.admin_request(request.to_string().as_bytes());
        serde_json::from_str(&answer).unwrap()
    }

    fn admin_ok(&mut self, request: Value) -> Value {
        let answer = self.admin(request.clone());
        assert_eq!(answer["ok"], json!(true), "{request} -> {answer}");
        answer["result"].clone()
    }

    fn issue(&mut self, grant: &Grant, uid: u32) -> (String, String) {
        self.issue_for(grant, uid, 3_600)
    }

    /// Issue a credential; the token comes beside the result, never in it.
    fn issue_for(&mut self, grant: &Grant, uid: u32, ttl_secs: u64) -> (String, String) {
        let answer = self.admin(json!({
            "op": "issue",
            "name": "test agent",
            "uid": uid,
            "grant": grant,
            "ttl_secs": ttl_secs,
        }));
        assert_eq!(answer["ok"], json!(true), "{answer}");
        assert!(answer["result"].get("token").is_none());
        (
            answer["result"]["id"].as_str().unwrap().to_string(),
            answer["token"].as_str().unwrap().to_string(),
        )
    }

    fn raw(&mut self, uid: u32, line: &str) -> (Option<Value>, bool) {
        let answer = self.state.agent_request(uid, line.as_bytes());
        (
            answer
                .line
                .map(|l| serde_json::from_str::<Value>(&l).unwrap()),
            answer.authenticated,
        )
    }

    fn send(&mut self, uid: u32, token: &str, message: Value) -> Option<Value> {
        let line = json!({ "token": token, "message": message }).to_string();
        self.raw(uid, &line).0
    }

    fn rpc(&mut self, token: &str, method: &str, params: Value) -> Value {
        self.send(
            AGENT,
            token,
            json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }),
        )
        .unwrap()
    }

    /// A tool call's result: its text parsed as JSON when it is, and whether
    /// it is an error.
    fn tool(&mut self, token: &str, name: &str, args: Value) -> (Value, bool) {
        let answer = self.rpc(
            token,
            "tools/call",
            json!({ "name": name, "arguments": args }),
        );
        let result = &answer["result"];
        assert!(result.is_object(), "{answer}");
        let text = result["content"][0]["text"].as_str().unwrap();
        let content = serde_json::from_str(text).unwrap_or(Value::String(text.into()));
        (content, result["isError"].as_bool().unwrap())
    }

    fn entries(&self, event: AuditEventType) -> Vec<AuditEntry> {
        self.state
            .keep()
            .audit_read_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event)
            .collect()
    }

    fn reasons(&self, event: AuditEventType) -> Vec<String> {
        self.entries(event)
            .into_iter()
            .filter_map(|e| e.reason)
            .collect()
    }

    fn break_log(&self, broken: bool) {
        let log = self.path().join("audit.log");
        if broken {
            std::fs::rename(&log, log.with_extension("bak")).unwrap();
            std::fs::create_dir(&log).unwrap();
        } else {
            std::fs::remove_dir(&log).unwrap();
            std::fs::rename(log.with_extension("bak"), &log).unwrap();
        }
    }

    fn spent(&self, ledger: &[u8]) -> u64 {
        self.state
            .keep()
            .load_agent_ledger(ledger)
            .unwrap()
            .map(|b| serde_json::from_slice::<crate::policy::Ledger>(&b).unwrap())
            .unwrap_or_default()
            .spent(self.state.now())
    }
}

fn nostr_grant(key: [u8; 32]) -> Grant {
    Grant {
        keys: [key].into(),
        operations: [Operation::GetPublicKey, Operation::SignNostrEvent].into(),
        event_kinds: [1, 0].into(),
        nip44_peers: Default::default(),
        bitcoin: None,
        limits: RequestLimits::default(),
    }
}

fn bitcoin_grant(key: [u8; 32]) -> Grant {
    Grant {
        keys: [key].into(),
        operations: [Operation::GetBitcoinAddress, Operation::SignPsbt].into(),
        event_kinds: Default::default(),
        nip44_peers: Default::default(),
        bitcoin: Some(BitcoinGrant {
            network: NETWORK,
            per_psbt_sats: 20_000,
            window_sats: 50_000,
            approval_above_sats: None,
            address_allowlist: None,
        }),
        limits: RequestLimits::default(),
    }
}

/// The uniform refusal, for request id `id`.
fn refused(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": REFUSED_CODE, "message": "request refused" }
    })
}

fn ping() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })
}

/// A testnet PSBT spending one of the key's own receive outputs of `in_sats`:
/// `pay_sats` to an outside address and the rest, less `fee`, to its change.
fn psbt(pay_sats: u64, in_sats: u64, fee: u64) -> String {
    use bitcoin::{
        absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, Psbt, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    let wallet = keep_bitcoin::AddressDerivation::new(&SECRET, NETWORK).unwrap();
    let fingerprint = wallet.master_fingerprint().unwrap();
    let receive = wallet.get_receive_address(0).unwrap();
    let change = wallet.get_change_address(0).unwrap();
    let payee = bitcoin::Address::p2tr(
        &bitcoin::key::Secp256k1::new(),
        bitcoin::secp256k1::Keypair::from_seckey_slice(&bitcoin::key::Secp256k1::new(), &[9; 32])
            .unwrap()
            .x_only_public_key()
            .0,
        None,
        NETWORK,
    );
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(pay_sats),
                script_pubkey: payee.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(in_sats - pay_sats - fee),
                script_pubkey: change.address.script_pubkey(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(in_sats),
        script_pubkey: receive.address.script_pubkey(),
    });
    psbt.inputs[0].tap_internal_key = Some(receive.public_key);
    psbt.inputs[0].tap_key_origins.insert(
        receive.public_key,
        (vec![], (fingerprint, receive.path.clone())),
    );
    psbt.outputs[1].tap_internal_key = Some(change.public_key);
    psbt.outputs[1].tap_key_origins.insert(
        change.public_key,
        (vec![], (fingerprint, change.path.clone())),
    );
    keep_bitcoin::psbt::serialize_psbt_base64(&psbt)
}

#[test]
fn an_agent_is_served_only_what_its_grant_allows_and_every_answer_is_recorded_first() {
    let mut g = Gw::new();
    let key = g.key;
    let (id, token) = g.issue(&nostr_grant(key), AGENT);

    let init = g.rpc(&token, "initialize", json!({}));
    assert_eq!(init["id"], json!(7));
    assert_eq!(init["result"]["serverInfo"]["name"], json!("keep-gateway"));
    let list = g.rpc(&token, "tools/list", json!({}));
    let mut names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["get_nostr_pubkey", "get_session_info", "sign_nostr_event"]
    );

    let (pubkey, err) = g.tool(&token, "get_nostr_pubkey", json!({}));
    assert!(!err);
    assert_eq!(pubkey["hex"], json!(hex::encode(key)));
    assert_eq!(pubkey["npub"], json!(keep_core::keys::bytes_to_npub(&key)));
    // The handshake and the public key were each recorded before they were
    // returned.
    assert_eq!(
        g.reasons(AuditEventType::AgentServed),
        [
            format!("agent {id} initialize"),
            format!("agent {id} tools/list"),
            format!("agent {id} get_nostr_pubkey \"{}\"", hex::encode(key)),
        ]
    );

    let (event, err) = g.tool(
        &token,
        "sign_nostr_event",
        json!({ "kind": 1, "content": "hello", "tags": [["t", "keep"]] }),
    );
    assert!(!err, "{event}");
    let event: nostr_sdk::Event = serde_json::from_value(event).unwrap();
    event.verify().unwrap();
    assert_eq!(event.pubkey.to_bytes(), key);
    assert_eq!(event.content, "hello");
    let signed = g.entries(AuditEventType::Sign);
    assert_eq!(signed.len(), 1);
    assert_eq!(
        signed[0].reason.as_deref(),
        Some(format!("agent {id} sign_nostr_event kind 1 id {}", event.id).as_str())
    );

    // Not granted: denied, and the agent is told why.
    let (why, err) = g.tool(
        &token,
        "sign_nostr_event",
        json!({ "kind": 4, "content": "" }),
    );
    assert!(err);
    assert_eq!(why, json!("denied: event kind 4 is not granted"));
    // Granted but always approved by a human: refused until approvals exist.
    let (why, err) = g.tool(
        &token,
        "sign_nostr_event",
        json!({ "kind": 0, "content": "{}" }),
    );
    assert!(err);
    assert!(why.as_str().unwrap().starts_with("needs approval"), "{why}");
    let (_, err) = g.tool(&token, "get_bitcoin_address", json!({}));
    assert!(err, "an operation outside the grant");
    let refusals = g.reasons(AuditEventType::AgentRefused);
    assert!(
        refusals
            .iter()
            .any(|r| r.contains("denied") && r.contains("kind 4")),
        "{refusals:?}"
    );
    assert!(
        refusals.iter().any(|r| r.contains("needs approval")),
        "{refusals:?}"
    );
    assert_eq!(
        g.entries(AuditEventType::Sign).len(),
        1,
        "nothing else signed"
    );

    let info = g.tool(&token, "get_session_info", json!({})).0;
    assert_eq!(info["id"], json!(id));
    assert_eq!(info["grant"]["keys"], json!([hex::encode(key)]));
    assert!(!info.to_string().contains(&token));
}

#[test]
fn malformed_requests_are_refused_and_recorded() {
    let mut g = Gw::new();
    let mut grant = nostr_grant(g.key);
    grant.limits.per_minute = 100;
    grant.limits.per_hour = 100;
    let (_, token) = g.issue(&grant, AGENT);
    let bad = |g: &mut Gw, args: Value| {
        let answer = g.rpc(
            &token,
            "tools/call",
            json!({ "name": "sign_nostr_event", "arguments": args }),
        );
        answer["error"]["code"].as_i64()
    };
    for args in [
        json!({ "content": "" }),
        json!({ "kind": 70_000, "content": "" }),
        json!({ "kind": -1, "content": "" }),
        json!({ "kind": 1 }),
        json!({ "kind": 1, "content": "", "tags": [[]] }),
        json!({ "kind": 1, "content": "", "tags": [[1]] }),
        json!({ "kind": 1, "content": "", "tags": "t" }),
        json!({ "kind": 1, "content": "", "created_at": 1 }),
        json!({ "kind": 1, "content": "", "key": "zz" }),
        json!([1]),
    ] {
        assert_eq!(bad(&mut g, args.clone()), Some(-32602), "{args}");
    }
    let unknown = g.rpc(&token, "tools/call", json!({ "name": "export_nsec" }));
    assert_eq!(unknown["error"]["code"], json!(-32602));
    let method = g.rpc(&token, "resources/read", json!({}));
    assert_eq!(method["error"]["code"], json!(-32601));
    let not_rpc = g
        .send(AGENT, &token, json!({ "id": 3, "method": "ping" }))
        .unwrap();
    assert_eq!(not_rpc["error"]["code"], json!(-32600));
    assert!(
        g.send(AGENT, &token, json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "sign_nostr_event", "arguments": { "kind": 1, "content": "x" } } }))
            .is_none(),
        "a notification is never answered or acted on"
    );
    assert!(g.entries(AuditEventType::Sign).is_empty());
    assert!(g
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.contains("invalid") && r.contains("export_nsec")));
}

#[test]
fn every_refused_token_gets_the_same_answer_and_matched_ones_are_recorded() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&nostr_grant(g.key), AGENT);
    let (expired_id, expired) = g.issue_for(&nostr_grant(g.key), AGENT, 1);
    g.boot.advance(2);
    let message = ping();
    let mut answers = Vec::new();
    // Another uid presenting a real token: a theft signal.
    answers.push(g.send(OTHER, &token, message.clone()));
    answers.push(g.send(AGENT, &expired, message.clone()));
    let mut unknown = token.clone();
    unknown.replace_range(20..21, if &token[20..21] == "a" { "b" } else { "a" });
    answers.push(g.send(AGENT, &unknown, message.clone()));
    answers.push(g.send(AGENT, "not a token", message.clone()));
    // uids no credential may be bound to, even with a real token.
    for uid in [
        0,
        HOST.euid,
        HOST.vault_owner,
        ADMIN,
        HOST.overflow_uid,
        u32::MAX,
    ] {
        answers.push(g.send(uid, &token, message.clone()));
    }
    for answer in &answers {
        assert_eq!(answer.as_ref(), Some(&refused(json!(1))));
    }
    for line in [
        "",
        "{",
        "[]",
        "{\"token\":1,\"message\":{}}",
        "{\"token\":\"x\",\"message\":{},\"x\":1}",
    ] {
        let (answer, authenticated) = g.raw(AGENT, line);
        assert_eq!(answer, Some(refused(Value::Null)), "{line}");
        assert!(!authenticated);
    }
    // Refusals of real tokens are recorded on the next tick, not before the
    // answer, so the answer takes as long as for an unknown token.
    assert!(g.reasons(AuditEventType::AgentRefused).is_empty());
    g.state.tick();
    let refusals = g.reasons(AuditEventType::AgentRefused);
    for uid in [
        0,
        HOST.euid,
        HOST.vault_owner,
        ADMIN,
        HOST.overflow_uid,
        u32::MAX,
    ] {
        assert!(
            refusals.contains(&format!(
                "agent {id} unauthenticated \"presented by uid {uid}\""
            )),
            "a real token from forbidden uid {uid} is a theft signal: {refusals:?}"
        );
    }
    assert!(
        refusals.contains(&format!(
            "agent {id} unauthenticated \"presented by uid {OTHER}\""
        )),
        "{refusals:?}"
    );
    assert!(refusals.contains(&format!("agent {expired_id} unauthenticated \"expired\"")));

    // Revoked, frozen and frozen all: the same answer, checked on every request.
    let (_, ok) = g.raw(
        AGENT,
        &json!({ "token": token, "message": ping() }).to_string(),
    );
    assert!(ok);
    g.admin_ok(json!({ "op": "freeze", "id": id }));
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    g.admin_ok(json!({ "op": "unfreeze", "id": id }));
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    g.admin_ok(json!({ "op": "freeze_all" }));
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    g.admin_ok(json!({ "op": "unfreeze_all" }));
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    g.admin_ok(json!({ "op": "revoke", "id": id }));
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    g.state.tick();
    let refusals = g.reasons(AuditEventType::AgentRefused);
    assert!(refusals.contains(&format!("agent {id} unauthenticated \"frozen\"")));
    assert!(refusals.contains(&format!("agent {id} unauthenticated \"revoked\"")));
}

#[test]
fn rate_limits_count_refused_requests_and_apply_per_uid_before_authentication() {
    let mut grant = nostr_grant([0; 32]);
    grant.limits = RequestLimits {
        per_minute: 3,
        per_hour: 100,
        per_day: 1_000,
    };
    let mut g = Gw::new();
    grant.keys = [g.key].into();
    let (id, token) = g.issue(&grant, AGENT);
    for _ in 0..2 {
        assert!(
            g.tool(
                &token,
                "sign_nostr_event",
                json!({ "kind": 4, "content": "" })
            )
            .1
        );
    }
    assert!(!g.tool(&token, "get_nostr_pubkey", json!({})).1);
    let limited = g.rpc(&token, "ping", json!({}));
    assert_eq!(limited["error"]["code"], json!(-32002), "{limited}");
    assert!(g.reasons(AuditEventType::AgentRefused).contains(&format!(
        "agent {id} rate limited \"over its per-minute limit\""
    )));
    g.boot.advance(60);
    assert!(g.rpc(&token, "ping", json!({})).get("result").is_some());

    // The uid's own limit covers every request, even ones no token backs.
    let mut s = settings();
    s.uid_limits = RequestLimits {
        per_minute: 2,
        per_hour: 100,
        per_day: 1_000,
    };
    let mut g = Gw::with(s);
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    assert_eq!(g.send(AGENT, "nope", ping()), Some(refused(json!(1))));
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(Value::Null)));
    assert!(
        g.send(OTHER, "nope", ping()).is_some(),
        "other uids are counted apart"
    );
}

#[test]
fn a_signature_or_answer_that_cannot_be_recorded_is_withheld() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    g.break_log(true);
    for (name, args) in [
        ("sign_nostr_event", json!({ "kind": 1, "content": "x" })),
        ("get_nostr_pubkey", json!({})),
        ("get_session_info", json!({})),
    ] {
        let answer = g.rpc(
            &token,
            "tools/call",
            json!({ "name": name, "arguments": args }),
        );
        assert_eq!(answer["error"]["code"], json!(-32603), "{answer}");
        assert_eq!(
            answer["error"]["message"],
            json!("the gateway could not complete the request"),
            "{answer}"
        );
        assert!(!answer.to_string().contains("\"sig\""));
    }
    for method in ["initialize", "tools/list"] {
        let answer = g.rpc(&token, method, json!({}));
        assert_eq!(
            answer["error"]["message"],
            json!("the gateway could not complete the request"),
            "{method}: {answer}"
        );
        assert!(answer.get("result").is_none());
    }
    g.break_log(false);
    assert!(g.entries(AuditEventType::Sign).is_empty());
}

#[test]
fn psbts_are_signed_within_the_grant_and_spends_are_persisted() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let cid: [u8; 16] = hex::decode(&id).unwrap().try_into().unwrap();
    let wallet = wallet_key(&g.key, NETWORK);

    let (address, err) = g.tool(
        &token,
        "get_bitcoin_address",
        json!({ "network": "testnet" }),
    );
    assert!(!err, "{address}");
    assert!(address["address"].as_str().unwrap().starts_with("tb1p"));
    let (_, err) = g.tool(
        &token,
        "get_bitcoin_address",
        json!({ "network": "mainnet" }),
    );
    assert!(err, "another network is denied");

    let (signed, err) = g.tool(
        &token,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(9_900, 100_000, 100) }),
    );
    assert!(!err, "{signed}");
    assert_eq!(signed["inputs_signed"], json!(1));
    assert_eq!(signed["leaving_wallet_sats"], json!(10_000));
    let back =
        keep_bitcoin::psbt::parse_psbt_base64(signed["signed_psbt"].as_str().unwrap()).unwrap();
    assert!(back.inputs[0].tap_key_sig.is_some());
    assert_eq!(g.spent(&cid), 10_000);
    assert_eq!(g.spent(&wallet), 10_000);
    assert!(g.reasons(AuditEventType::Sign)[0].contains("leaving 10000 sats fee 100 sats"));

    // Over the per-PSBT cap, fee included.
    let (why, err) = g.tool(
        &token,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(19_950, 100_000, 100) }),
    );
    assert!(err);
    assert!(
        why.as_str().unwrap().contains("over the 20000 sat limit"),
        "{why}"
    );
    // The credential's window budget is cumulative.
    for _ in 0..2 {
        assert!(
            !g.tool(
                &token,
                "sign_bitcoin_psbt",
                json!({ "psbt": psbt(19_900, 100_000, 100) })
            )
            .1
        );
    }
    let (why, err) = g.tool(
        &token,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(900, 100_000, 100) }),
    );
    assert!(err);
    assert!(
        why.as_str()
            .unwrap()
            .contains("exceeds the 50000 sat budget"),
        "{why}"
    );
    assert_eq!(g.spent(&cid), 50_000);

    // A restart keeps the spends.
    let mut g = g.restart(BOOT, T0).unwrap();
    let (why, err) = g.tool(
        &token,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(900, 100_000, 100) }),
    );
    assert!(err, "{why}");
    assert_eq!(g.spent(&cid), 50_000);
}

#[test]
fn the_wallet_budget_spans_credentials_and_zero_refuses_every_spend() {
    let mut s = settings();
    s.wallet_budget_sats = 50_000;
    let mut g = Gw::with(s);
    let (_, a) = g.issue(&bitcoin_grant(g.key), AGENT);
    let (_, b) = g.issue(&bitcoin_grant(g.key), OTHER);
    for _ in 0..3 {
        assert!(
            !g.tool(
                &a,
                "sign_bitcoin_psbt",
                json!({ "psbt": psbt(14_900, 100_000, 100) })
            )
            .1
        );
    }
    let send_b = |g: &mut Gw, sats| {
        let line = json!({ "token": b, "message": {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "sign_bitcoin_psbt", "arguments": { "psbt": psbt(sats, 100_000, 100) } }
        }});
        g.raw(OTHER, &line.to_string()).0.unwrap()["result"].clone()
    };
    assert_eq!(
        send_b(&mut g, 4_900)["isError"],
        json!(false),
        "exactly at the wallet budget"
    );
    let over = send_b(&mut g, 900);
    assert_eq!(over["isError"], json!(true));
    // The agent is not told what other credentials spent; the log is.
    assert!(
        over.to_string()
            .contains("this spend would exceed the wallet's budget"),
        "{over}"
    );
    assert!(!over.to_string().contains("50000"), "{over}");
    assert!(
        g.reasons(AuditEventType::AgentRefused)
            .iter()
            .any(|r| r.contains("on top of 50000 already spent") && r.contains("50000 sat budget")),
        "{:?}",
        g.reasons(AuditEventType::AgentRefused)
    );

    let mut s = settings();
    s.wallet_budget_sats = 0;
    let mut g = Gw::with(s);
    let (_, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let (why, err) = g.tool(
        &token,
        "sign_bitcoin_psbt",
        json!({ "psbt": psbt(100, 100_000, 100) }),
    );
    assert!(err);
    assert!(
        why.as_str().unwrap().contains("exceed the wallet's budget"),
        "{why}"
    );
}

#[test]
fn a_spend_whose_signature_cannot_be_recorded_is_released() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let cid: [u8; 16] = hex::decode(&id).unwrap().try_into().unwrap();
    g.break_log(true);
    let answer = g.rpc(
        &token,
        "tools/call",
        json!({ "name": "sign_bitcoin_psbt", "arguments": { "psbt": psbt(9_900, 100_000, 100) } }),
    );
    assert_eq!(answer["error"]["code"], json!(-32603), "{answer}");
    assert!(!answer.to_string().contains("signed_psbt"));
    g.break_log(false);
    assert_eq!(g.spent(&cid), 0, "the reservation was returned");
    assert_eq!(g.spent(&wallet_key(&g.key, NETWORK)), 0);
}

#[test]
fn a_psbt_with_nothing_to_sign_spends_nothing() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let cid: [u8; 16] = hex::decode(&id).unwrap().try_into().unwrap();
    let mut foreign = keep_bitcoin::psbt::parse_psbt_base64(&psbt(9_900, 100_000, 100)).unwrap();
    foreign.inputs[0].tap_key_origins.clear();
    foreign.inputs[0].tap_internal_key = None;
    let answer = g.rpc(
        &token,
        "tools/call",
        json!({ "name": "sign_bitcoin_psbt", "arguments": {
            "psbt": keep_bitcoin::psbt::serialize_psbt_base64(&foreign) } }),
    );
    assert_eq!(answer["error"]["code"], json!(-32602), "{answer}");
    assert_eq!(g.spent(&cid), 0);
    assert!(g.entries(AuditEventType::Sign).is_empty());
}

#[test]
fn admin_issue_refuses_uids_that_would_stop_nothing_and_keys_not_in_the_vault() {
    let mut g = Gw::new();
    for uid in [
        0,
        HOST.euid,
        HOST.vault_owner,
        ADMIN,
        HOST.overflow_uid,
        u32::MAX,
    ] {
        let answer = g.admin(json!({
            "op": "issue", "name": "x", "uid": uid, "grant": nostr_grant(g.key)
        }));
        assert_eq!(answer["ok"], json!(false), "uid {uid}: {answer}");
    }
    let answer = g.admin(json!({
        "op": "issue", "name": "x", "uid": AGENT, "grant": nostr_grant([3; 32])
    }));
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .contains("not in the vault"),
        "{answer}"
    );
    let mut invalid = nostr_grant(g.key);
    invalid.event_kinds.clear();
    let answer = g.admin(json!({ "op": "issue", "name": "x", "uid": AGENT, "grant": invalid }));
    assert_eq!(answer["ok"], json!(false));
    for bad in [
        json!({ "op": "drop_tables" }),
        json!({ "op": "list", "extra": 1 }),
        json!({ "op": "freeze" }),
        json!({ "op": "revoke", "id": "xyz" }),
        json!({ "op": "revoke", "id": "00".repeat(16) }),
    ] {
        assert_eq!(g.admin(bad.clone())["ok"], json!(false), "{bad}");
    }
    assert!(g.state.keep().agent_credentials().unwrap().is_empty());

    let answer = g.admin(json!({
        "op": "issue", "name": "x", "uid": AGENT, "grant": nostr_grant(g.key)
    }));
    assert_eq!(
        answer["result"]["expires_at"],
        json!(T0 + super::state::DEFAULT_TTL_SECS)
    );
    let token = answer["token"].as_str().unwrap().to_string();
    assert!(token.starts_with(keep_core::agent::TOKEN_PREFIX));
    let list = g.admin_ok(json!({ "op": "list" }));
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(
        !list.to_string().contains(&token),
        "list never shows a token"
    );
    assert_eq!(list[0]["uid"], json!(AGENT));
    let status = g.admin_ok(json!({ "op": "status" }));
    assert_eq!(status["credentials"], json!(1));
    assert_eq!(status["frozen"], json!(false));
    let audit = g.admin_ok(json!({ "op": "audit", "limit": 1 }));
    assert_eq!(audit.as_array().unwrap().len(), 1);
    assert_eq!(audit[0]["event"], json!("agent_credential_issue"));
    let id = list[0]["id"].as_str().unwrap().to_string();
    g.admin_ok(json!({ "op": "delete", "id": id }));
    assert!(g
        .admin_ok(json!({ "op": "list" }))
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn start_refuses_what_it_cannot_serve_safely() {
    let dir = tempfile::tempdir().unwrap();
    let boot = FakeBoot::default();
    let err = |keep, settings: Settings, host: Host| {
        State::start(
            keep,
            settings,
            host,
            Box::new(FakeBoot::default()),
            BOOT.into(),
        )
        .err()
        .unwrap()
        .to_string()
    };
    let (keep, _) = vault(dir.path());
    let root = Host { euid: 0, ..HOST };
    assert!(err(keep, settings(), root).contains("not root"));
    for admin in [HOST.euid, 0, HOST.overflow_uid] {
        let (keep, _) = vault(dir.path());
        let s = Settings {
            admin_uid: Some(admin),
            ..settings()
        };
        assert!(err(keep, s, HOST).contains("admin uid"), "{admin}");
    }
    let (mut keep, _) = vault(dir.path());
    keep.lock();
    assert!(err(keep, settings(), HOST).contains("locked"));
    let (keep, _) = vault(dir.path());
    keep.corrupt_agent_freeze_for_testing().unwrap();
    assert!(err(keep, settings(), HOST).contains("agent freeze cannot be read"));
    let (mut keep, _) = vault(dir.path());
    keep.set_agent_freeze(false).unwrap();
    drop(keep);

    // A live credential bound to a uid it cannot protect against.
    let (mut keep, key) = vault(dir.path());
    let grant = serde_json::to_vec(&nostr_grant(key)).unwrap();
    let (bad, _) = keep
        .issue_agent_credential("bad", HOST.vault_owner, grant, T0, 3_600)
        .unwrap();
    assert!(err(keep, settings(), HOST).contains(&bad.id_hex()));
    let (mut keep, key) = vault(dir.path());
    keep.revoke_agent_credential(&bad.id).unwrap();
    // One that has expired serves nothing, so it does not stop a start.
    let grant = serde_json::to_vec(&nostr_grant(key)).unwrap();
    keep.issue_agent_credential("old", HOST.vault_owner, grant, T0 - 10_000, 3_600)
        .unwrap();
    start(keep, settings(), &boot, BOOT).unwrap();
}

#[test]
fn the_budget_clock_counts_only_running_time_whatever_the_wall_clock() {
    let g = Gw::new();
    g.boot.advance(500);
    // Same boot: continued by boot time, the wall clock far ahead or behind.
    let g = g.restart(BOOT, T0 + 1_000 * 86_400).unwrap();
    assert_eq!(g.state.now(), T0 + 500);
    assert_eq!(
        g.state.calendar(),
        T0 + 1_000 * 86_400,
        "credentials see it"
    );
    let g = g.restart(BOOT, 0).unwrap();
    assert_eq!(g.state.now(), T0 + 500);
    assert_eq!(
        g.state.calendar(),
        T0 + 1_000 * 86_400,
        "the calendar never goes back"
    );
    // A reboot resumes from what the vault saw, behind or ahead.
    let g = g.restart(REBOOT, T0).unwrap();
    assert_eq!(g.state.now(), T0 + 500);
    let g = g.restart(BOOT, T0 + 23 * 3_600).unwrap();
    assert_eq!(g.state.now(), T0 + 500);
    let stored = g
        .state
        .keep()
        .load_agent_ledger(HEARTBEAT_KEY)
        .unwrap()
        .unwrap();
    assert_eq!(Heartbeat::decode(&stored).unwrap().clock, T0 + 500);

    // A heartbeat that does not decode is ignored: the ledgers hold budgets.
    let Gw {
        dir, boot, state, ..
    } = g;
    drop(state);
    let (mut keep, _) = vault(dir.path());
    keep.update_agent_ledgers(&[HEARTBEAT_KEY], |_| Ok(vec![b"junk".to_vec()]))
        .unwrap();
    drop(keep);
    let (keep, _) = vault(dir.path());
    assert!(start(keep, settings(), &boot, REBOOT).is_ok());
}

/// The reviewer's scenario: an agent spends its whole window, the host
/// reboots, and the wall clock comes back a day ahead. The budget stays spent
/// until a day of the gateway's own running time has passed.
#[test]
fn a_spent_budget_stays_spent_across_a_reboot_with_the_clock_ahead() {
    let mut g = Gw::new();
    let (_, token) = g.issue_for(&bitcoin_grant(g.key), AGENT, 30 * 86_400);
    for _ in 0..2 {
        assert!(
            !g.tool(
                &token,
                "sign_bitcoin_psbt",
                json!({ "psbt": psbt(19_900, 100_000, 100) })
            )
            .1
        );
    }
    assert!(
        !g.tool(
            &token,
            "sign_bitcoin_psbt",
            json!({ "psbt": psbt(9_900, 100_000, 100) })
        )
        .1
    );
    let spend = |g: &mut Gw| {
        g.tool(
            &token,
            "sign_bitcoin_psbt",
            json!({ "psbt": psbt(900, 100_000, 100) }),
        )
        .1
    };
    assert!(spend(&mut g), "the window is spent");
    g.boot.advance(3_600);
    // (Far enough ahead and the credential itself expires, on the calendar.)
    for wall in [T0 + 86_400, T0 + 2 * 86_400, T0 + 20 * 86_400] {
        g = g.restart(REBOOT, wall).unwrap();
        assert!(spend(&mut g), "still spent with the wall clock at {wall}");
    }
    g.boot.advance(86_400 - 3_600);
    assert!(!spend(&mut g), "a day of running time later");
}

/// A credential issued while the wall clock ran ahead is stamped on the
/// calendar, and does not drag the budget clock forward on the next start.
#[test]
fn issue_times_never_move_the_budget_clock() {
    let mut g = Gw::new();
    g.boot.set_wall(T0 + 10 * 86_400);
    let (_, token) = g.issue_for(&nostr_grant(g.key), AGENT, 30 * 86_400);
    let g = g.restart(REBOOT, T0 + 10 * 86_400).unwrap();
    assert_eq!(g.state.now(), T0, "the budget clock stays where it was");
    let mut g = g;
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
}

/// The reviewers' scenario: a credential is issued after downtime has put
/// the budget clock behind real time, and the next boot's wall clock reads
/// 1970. The credential is neither locked out nor kept alive past its expiry.
#[test]
fn a_wall_clock_behind_after_a_reboot_neither_locks_out_nor_extends_credentials() {
    let mut g = Gw::new();
    // Ten days down: the budget clock stays at T0, real time moves on.
    let day = 86_400;
    g = g.restart(REBOOT, T0 + 10 * day).unwrap();
    assert_eq!(g.state.now(), T0);
    let (_, token) = g.issue_for(&nostr_grant(g.key), AGENT, 2 * day);
    let mut g = g.restart(REBOOT, 0).unwrap();
    assert!(
        g.send(AGENT, &token, ping())
            .unwrap()
            .get("result")
            .is_some(),
        "not locked out"
    );
    g.boot.advance(2 * day);
    assert_eq!(
        g.send(AGENT, &token, ping()),
        Some(refused(json!(1))),
        "expired after two days of running time"
    );
}

/// With the heartbeat lost, issue times alone hold the calendar: a wall clock
/// behind still does not lock credentials out.
#[test]
fn issue_times_hold_the_calendar_without_a_heartbeat() {
    let mut g = Gw::new();
    g = g.restart(REBOOT, T0 + 10 * 86_400).unwrap();
    let (_, token) = g.issue_for(&nostr_grant(g.key), AGENT, 2 * 86_400);
    let Gw {
        dir,
        boot,
        mut state,
        ..
    } = g;
    state.shut_down();
    state
        .keep_mut()
        .update_agent_ledgers(&[HEARTBEAT_KEY], |_| Ok(vec![b"junk".to_vec()]))
        .unwrap();
    drop(state);
    let (keep, key) = vault(dir.path());
    boot.set_wall(0);
    let state = start(keep, settings(), &boot, REBOOT).unwrap();
    let mut g = Gw {
        dir,
        boot,
        state,
        key,
    };
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    let status = g.admin_ok(json!({ "op": "status" }));
    assert_eq!(status["heartbeat_ignored_at_start"], json!(true));
}

/// Credentials expire on the calendar clock, which a reboot does not hold
/// back: a credential does not outlive its expiry by the gateway's downtime.
#[test]
fn credentials_expire_on_the_calendar_across_a_reboot() {
    let mut g = Gw::new();
    let (_, token) = g.issue_for(&nostr_grant(g.key), AGENT, 3_600);
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    let mut g = g.restart(REBOOT, T0 + 2 * 3_600).unwrap();
    assert_eq!(g.state.now(), T0, "the budget clock did not move");
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    // The expiry was seen: the next tick persists the calendar, so even a
    // crash right after cannot bring it back behind the expiry.
    let stored = |g: &Gw| {
        Heartbeat::decode(
            &g.state
                .keep()
                .load_agent_ledger(HEARTBEAT_KEY)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    let before = stored(&g);
    g.boot.advance(30);
    g.state.tick();
    assert!(
        stored(&g).boottime > before.boottime,
        "persisted on the tick"
    );
    // A wall clock behind on the next boot, or stepped back while running,
    // does not bring it back.
    let mut g = g.restart(REBOOT, 0).unwrap();
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    g.boot.set_wall(T0);
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    g.state.tick();
    assert!(g
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.ends_with("unauthenticated \"expired\"")));
}

#[test]
fn a_ledger_ahead_of_the_wall_clock_holds_the_clock() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    g.boot.advance(1_000);
    assert!(
        !g.tool(
            &token,
            "sign_bitcoin_psbt",
            json!({ "psbt": psbt(900, 100_000, 100) })
        )
        .1
    );
    // Drop the heartbeat: the ledgers alone still hold the clock.
    g.state
        .keep_mut()
        .update_agent_ledgers(&[HEARTBEAT_KEY], |_| {
            Ok(vec![Heartbeat {
                boot_id: BOOT.into(),
                boottime: 0,
                clock: 0,
                calendar: 0,
            }
            .encode()
            .unwrap()])
        })
        .unwrap();
    let Gw {
        dir, boot, state, ..
    } = g;
    drop(state);
    let (keep, _) = vault(dir.path());
    boot.set_wall(T0);
    let state = start(keep, settings(), &boot, REBOOT).unwrap();
    assert_eq!(state.now(), T0 + 1_000);
}

#[test]
fn a_stopped_gateway_serves_nothing() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    g.state.shut_down();
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(Value::Null)));
    assert_eq!(g.admin(json!({ "op": "status" }))["ok"], json!(false));
}

/// The sockets, driven over real Unix connections. The peer uid is whatever
/// this test runs as: as root, or as the admin, the agent socket must refuse
/// it; as any other user, it is served.
mod sockets {
    use super::*;
    use crate::gateway::daemon::server::{self, Limits, MAX_LINE};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn my_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn socket_dir(root: &std::path::Path, name: &str, mode: u32) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[tokio::test]
    async fn sockets_bind_only_in_a_closed_directory_owned_by_the_gateway() {
        let root = tempfile::tempdir().unwrap();
        let me = my_uid();
        let open = socket_dir(root.path(), "open", 0o755);
        let err = server::bind(&open.join("s"), me).err().unwrap().to_string();
        assert!(err.contains("closed to others"), "{err}");
        let group_writable = socket_dir(root.path(), "group", 0o770);
        let err = server::bind(&group_writable.join("s"), me)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("writable by the gateway alone"), "{err}");
        let closed = socket_dir(root.path(), "closed", 0o750);
        let err = server::bind(&closed.join("s"), me + 1)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("owned by uid"), "{err}");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&closed, &link).unwrap();
        assert!(
            server::bind(&link.join("s"), me).is_err(),
            "a symlinked directory"
        );
        std::fs::write(closed.join("file"), b"x").unwrap();
        assert!(
            server::bind(&closed.join("file"), me).is_err(),
            "a file in the way"
        );
        assert!(server::bind(&closed.join("file").join("s"), me).is_err());

        let path = closed.join("agent.sock");
        let live = server::bind(&path, me).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666, "access is the directory's");
        let err = server::bind(&path, me).err().unwrap().to_string();
        assert!(err.contains("another gateway"), "{err}");
        drop(live);
        // The file of a gateway that died is stale and replaced.
        assert!(path.exists());
        server::bind(&path, me).unwrap();
    }

    struct Running {
        _root: tempfile::TempDir,
        agent: PathBuf,
        admin: PathBuf,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<crate::error::Result<()>>,
        token: Option<String>,
        vault: PathBuf,
    }

    fn limits() -> Limits {
        Limits {
            connections_per_uid: 2,
            unbound_connections: 2,
            connections: 4,
            admin_connections: 1,
            pre_auth: Duration::from_millis(400),
            idle: Duration::from_secs(5),
            admin_idle: Duration::from_secs(5),
            write: Duration::from_secs(5),
            refusals_in_a_row: 3,
        }
    }

    /// A gateway on fresh sockets. When this test's uid can hold a
    /// credential, one is issued to it before serving.
    async fn running(admin_uid: Option<u32>) -> Running {
        running_with(admin_uid, limits()).await
    }

    /// Limits under which only the check a test exercises can close a
    /// connection within [`Conn::recv`]'s wait: the pre-auth deadline is far
    /// longer.
    fn patient() -> Limits {
        Limits {
            pre_auth: Duration::from_secs(60),
            idle: Duration::from_secs(60),
            ..limits()
        }
    }

    async fn running_with(admin_uid: Option<u32>, limits: Limits) -> Running {
        let root = tempfile::tempdir().unwrap();
        let me = my_uid();
        let agent_dir = socket_dir(root.path(), "agent", 0o750);
        let admin_dir = socket_dir(root.path(), "admin", 0o750);
        let (keep, key) = vault(root.path());
        let boot = FakeBoot::default();
        let s = Settings {
            admin_uid,
            ..settings()
        };
        boot.set_wall(T0);
        let mut state = start(keep, s, &boot, BOOT).unwrap();
        let can_hold = keep_core::agent::bindable_uid(me) && admin_uid != Some(me);
        let token = can_hold.then(|| {
            let answer = state.admin_request(
                json!({ "op": "issue", "name": "sock", "uid": me, "grant": nostr_grant(key) })
                    .to_string()
                    .as_bytes(),
            );
            let answer: Value = serde_json::from_str(&answer).unwrap();
            answer["token"].as_str().unwrap().to_string()
        });
        let agent = agent_dir.join("agent.sock");
        let admin = admin_dir.join("admin.sock");
        let agent_listener = server::bind(&agent, me).unwrap();
        let admin_listener = server::bind(&admin, me).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(server::serve(
            state,
            agent_listener,
            admin_listener,
            limits,
            async {
                let _ = stopped.await;
            },
        ));
        Running {
            agent,
            admin,
            stop: Some(stop),
            task,
            token,
            vault: root.path().join("keep"),
            _root: root,
        }
    }

    struct Conn {
        read: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        write: tokio::net::unix::OwnedWriteHalf,
    }

    impl Conn {
        async fn open(path: &std::path::Path) -> Self {
            let (read, write) = UnixStream::connect(path).await.unwrap().into_split();
            Self {
                read: BufReader::new(read).lines(),
                write,
            }
        }

        async fn send(&mut self, line: &str) {
            let _ = self.write.write_all(format!("{line}\n").as_bytes()).await;
        }

        /// The next answer, or `None` once the gateway has closed the
        /// connection.
        async fn recv(&mut self) -> Option<Value> {
            match tokio::time::timeout(Duration::from_secs(5), self.read.next_line()).await {
                Ok(Ok(Some(line))) => Some(serde_json::from_str(&line).unwrap()),
                Ok(_) => None,
                Err(_) => panic!("no answer and not closed"),
            }
        }

        async fn ask(&mut self, token: &str, message: Value) -> Option<Value> {
            self.send(&json!({ "token": token, "message": message }).to_string())
                .await;
            self.recv().await
        }
    }

    impl Running {
        /// Stop the gateway; the vault is kept until the returned directory
        /// drops.
        async fn stop(mut self) -> (crate::error::Result<()>, tempfile::TempDir) {
            let _ = self.stop.take().unwrap().send(());
            let result = tokio::time::timeout(Duration::from_secs(10), self.task)
                .await
                .unwrap()
                .unwrap();
            (result, self._root)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agent_socket_serves_by_peer_uid_and_closes_idle_or_refused_connections() {
        let gw = running(None).await;
        let mut c = Conn::open(&gw.agent).await;
        match &gw.token {
            Some(token) => {
                let answer = c.ask(token, ping()).await.unwrap();
                assert_eq!(answer["result"], json!({}), "{answer}");
                // Authenticated: the pre-auth deadline no longer applies.
                tokio::time::sleep(Duration::from_millis(600)).await;
                let answer = c.ask(token, ping()).await.unwrap();
                assert_eq!(answer["result"], json!({}));
            }
            None => {
                // Root: refused whatever token it holds.
                let answer = c.ask("keep_agt_x", ping()).await;
                assert_eq!(answer, Some(refused(json!(1))));
            }
        }

        // Nothing sent: closed at the pre-auth deadline.
        let mut idle = Conn::open(&gw.agent).await;
        assert!(idle.recv().await.is_none());

        drop(c);
        gw.stop().await.0.unwrap();
    }

    /// Each of these closes a connection by itself: the pre-auth deadline is a
    /// minute away, and every wait below is five seconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refusals_long_lines_and_extra_connections_are_closed_at_once() {
        let gw = running_with(None, patient()).await;

        // Three refusals in a row close the connection.
        let mut guessing = Conn::open(&gw.agent).await;
        for _ in 0..3 {
            assert_eq!(guessing.ask("nope", ping()).await, Some(refused(json!(1))));
        }
        assert!(guessing.recv().await.is_none());

        // Blank lines are refused requests too, not free.
        let mut blank = Conn::open(&gw.agent).await;
        blank.send("\n\n").await;
        assert_eq!(blank.recv().await, Some(refused(Value::Null)));
        assert_eq!(blank.recv().await, Some(refused(Value::Null)));
        assert_eq!(blank.recv().await, Some(refused(Value::Null)));
        assert!(blank.recv().await.is_none());

        // A line one byte past the limit, newline included, closes the
        // connection unanswered.
        let mut long = Conn::open(&gw.agent).await;
        long.send(&"a".repeat(MAX_LINE + 1)).await;
        assert!(long.recv().await.is_none());

        // After a token was accepted, refusals in a row still close it.
        if let Some(token) = &gw.token {
            let mut c = Conn::open(&gw.agent).await;
            assert!(c.ask(token, ping()).await.unwrap().get("result").is_some());
            for _ in 0..3 {
                assert_eq!(c.ask("nope", ping()).await, Some(refused(json!(1))));
            }
            assert!(c.recv().await.is_none());
        }

        // Two connections per uid: a third is closed at once.
        let first = Conn::open(&gw.agent).await;
        let second = Conn::open(&gw.agent).await;
        let mut third = Conn::open(&gw.agent).await;
        assert!(third.recv().await.is_none());
        drop((first, second));

        gw.stop().await.0.unwrap();
    }

    /// A client connects only to a socket served by the owner of a directory
    /// no one else can write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clients_connect_only_to_the_directory_owners_socket() {
        let gw = running(Some(my_uid()).filter(|&u| u != 0)).await;
        let me = my_uid();
        let checked = |p: &std::path::Path, uid: u32| {
            server::connect_checked(p, uid)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        checked(&gw.admin, me).unwrap();
        // Another expected gateway user: the directory and peer are not it.
        assert!(checked(&gw.admin, me + 1)
            .unwrap_err()
            .contains("is owned by uid"));
        let dir = gw.admin.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(checked(&gw.admin, me)
            .unwrap_err()
            .contains("could replace the socket"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        if me == 0 {
            // A directory the expected user owns, served by root: an impostor.
            std::os::unix::fs::chown(&dir, Some(4_321), None).unwrap();
            assert!(checked(&gw.admin, 4_321)
                .unwrap_err()
                .contains("served by uid 0"));
            std::os::unix::fs::chown(&dir, Some(0), None).unwrap();
        }
        assert!(checked(&gw.admin.with_file_name("missing.sock"), me).is_err());
        gw.stop().await.0.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_admin_socket_admits_only_root_and_the_admin_uid() {
        let me = my_uid();
        // Not root and not the admin: closed without an answer.
        if me != 0 {
            let gw = running(None).await;
            let mut c = Conn::open(&gw.admin).await;
            c.send(&json!({ "op": "status" }).to_string()).await;
            assert!(c.recv().await.is_none());
            gw.stop().await.0.unwrap();
        }
        let admin = (me != 0).then_some(me);
        let gw = running(admin).await;
        let mut c = Conn::open(&gw.admin).await;
        c.send(&json!({ "op": "status" }).to_string()).await;
        let status = c.recv().await.unwrap();
        assert_eq!(status["ok"], json!(true), "{status}");
        c.send(&json!({ "op": "freeze_all" }).to_string()).await;
        assert_eq!(c.recv().await.unwrap()["ok"], json!(true));
        let vault = gw.vault.clone();
        drop(c);
        let (stopped, _root) = gw.stop().await;
        stopped.unwrap();
        // The freeze was persisted and the clock written on the way out.
        let mut keep = Keep::open(&vault).unwrap();
        keep.unlock("testpass").unwrap();
        assert!(keep.agent_freeze().unwrap());
        assert!(keep.load_agent_ledger(HEARTBEAT_KEY).unwrap().is_some());
    }
}

/// A credential bound to a uid it cannot protect against, planted after
/// start, is still refused on every request.
#[test]
fn a_credential_bound_to_a_forbidden_uid_is_refused_per_request() {
    let mut g = Gw::new();
    let grant = serde_json::to_vec(&nostr_grant(g.key).validated().unwrap()).unwrap();
    for uid in [HOST.euid, HOST.vault_owner, ADMIN] {
        let (_, token) = g
            .state
            .keep_mut()
            .issue_agent_credential("planted", uid, grant.clone(), T0, 3_600)
            .unwrap();
        assert_eq!(
            g.send(uid, &token, ping()),
            Some(refused(json!(1))),
            "uid {uid}"
        );
    }
    assert!(g.entries(AuditEventType::AgentServed).is_empty());
    g.state.tick();
    let refusals = g.reasons(AuditEventType::AgentRefused);
    for uid in [HOST.euid, HOST.vault_owner, ADMIN] {
        assert!(
            refusals.iter().any(|r| r.contains(&format!(
                "presented by uid {uid}, which may hold no credential"
            ))),
            "{refusals:?}"
        );
    }
}

/// A public key is served only for a granted key, and only under a grant
/// that allows it.
#[test]
fn a_public_key_is_served_only_for_a_granted_key() {
    let mut g = Gw::new();
    let other = g
        .state
        .keep_mut()
        .import_secret_bytes(&mut [8; 32], "other")
        .unwrap();
    let mut grant = nostr_grant(g.key);
    grant.limits.per_minute = 100;
    grant.limits.per_hour = 100;
    let (_, token) = g.issue(&grant, AGENT);
    let (why, err) = g.tool(
        &token,
        "get_nostr_pubkey",
        json!({ "key": hex::encode(other) }),
    );
    assert!(err);
    assert_eq!(why, json!("denied: that key is not granted"));
    let (why, err) = g.tool(
        &token,
        "get_nostr_pubkey",
        json!({ "key": keep_core::keys::bytes_to_npub(&other) }),
    );
    assert!(err, "{why}");
    let (_, err) = g.tool(
        &token,
        "get_nostr_pubkey",
        json!({ "key": hex::encode(g.key) }),
    );
    assert!(!err);

    // Two granted keys: the request must name one.
    let mut both = grant.clone();
    both.keys.insert(other);
    let (_, token) = g.issue(&both, AGENT);
    let answer = g.rpc(&token, "tools/call", json!({ "name": "get_nostr_pubkey" }));
    assert_eq!(answer["error"]["code"], json!(-32602), "{answer}");

    // A grant without get_public_key.
    let (_, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let (why, err) = g.tool(&token, "get_nostr_pubkey", json!({}));
    assert!(err);
    assert_eq!(why, json!("denied: get_public_key is not granted"));
    assert_eq!(
        g.reasons(AuditEventType::AgentServed)
            .iter()
            .filter(|r| r.contains("get_nostr_pubkey"))
            .count(),
        1
    );
}

/// A request with an id but no method is answered, so the client is not left
/// waiting.
#[test]
fn a_request_without_a_method_is_answered() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    let answer = g
        .send(AGENT, &token, json!({ "jsonrpc": "2.0", "id": 5 }))
        .unwrap();
    assert_eq!(answer["id"], json!(5));
    assert_eq!(answer["error"]["code"], json!(-32600));
    assert!(g.send(AGENT, &token, json!({ "jsonrpc": "2.0" })).is_none());
}

/// Spends of test coins are counted apart from mainnet. The test networks,
/// which share the wallet's keys, share one ledger.
#[test]
fn mainnet_has_its_own_wallet_budget() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    assert!(
        !g.tool(
            &token,
            "sign_bitcoin_psbt",
            json!({ "psbt": psbt(9_900, 100_000, 100) })
        )
        .1
    );
    assert_eq!(
        g.spent(&wallet_key(&g.key, keep_bitcoin::Network::Bitcoin)),
        0
    );
    for network in [
        keep_bitcoin::Network::Testnet,
        keep_bitcoin::Network::Testnet4,
        keep_bitcoin::Network::Signet,
        keep_bitcoin::Network::Regtest,
    ] {
        assert_eq!(g.spent(&wallet_key(&g.key, network)), 10_000, "{network}");
    }
}

/// A request the gateway cannot complete is recorded as failed, and the agent
/// learns only that it failed.
#[test]
fn a_failed_request_is_recorded_and_its_detail_kept_from_the_agent() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&bitcoin_grant(g.key), AGENT);
    let cid: [u8; 16] = hex::decode(&id).unwrap().try_into().unwrap();
    g.state
        .keep_mut()
        .update_agent_ledgers(&[&cid], |_| Ok(vec![b"not a ledger".to_vec()]))
        .unwrap();
    let answer = g.rpc(
        &token,
        "tools/call",
        json!({ "name": "sign_bitcoin_psbt", "arguments": { "psbt": psbt(9_900, 100_000, 100) } }),
    );
    assert_eq!(
        answer["error"],
        json!({ "code": -32603, "message": "the gateway could not complete the request" })
    );
    assert!(g
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.starts_with(&format!("agent {id} failed")) && r.contains("ledger")));
    assert!(g.entries(AuditEventType::Sign).is_empty());
}

/// Refusals deferred for a credential deleted before the tick are dropped.
#[test]
fn deferred_refusals_of_a_deleted_credential_are_dropped() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&nostr_grant(g.key), AGENT);
    assert_eq!(g.send(OTHER, &token, ping()), Some(refused(json!(1))));
    g.admin_ok(json!({ "op": "delete", "id": id }));
    g.state.tick();
    assert!(!g
        .reasons(AuditEventType::AgentRefused)
        .iter()
        .any(|r| r.contains(&id)));
}

/// A vault fault while authenticating (here, credentials that cannot be
/// read) is answered with the same refusal as a bad token.
#[test]
fn a_vault_fault_during_authentication_is_a_uniform_refusal() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    g.state.keep_mut().lock();
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
}

/// Every uid no credential is bound to shares one request allowance, so an
/// agent controlling many uids can neither fill the uid tracker nor use up a
/// bound uid's requests. A uid stops being bound when its credential is
/// deleted.
#[test]
fn unbound_uids_share_one_allowance_and_cannot_crowd_out_a_bound_uid() {
    let mut s = settings();
    s.uid_limits = RequestLimits {
        per_minute: 2,
        per_hour: 100,
        per_day: 1_000,
    };
    let mut g = Gw::with(s);
    let (id, token) = g.issue(&nostr_grant(g.key), AGENT);
    assert_eq!(g.send(5_000, "nope", ping()), Some(refused(json!(1))));
    assert_eq!(g.send(5_001, "nope", ping()), Some(refused(json!(1))));
    assert_eq!(
        g.send(5_002, "nope", ping()),
        Some(refused(Value::Null)),
        "the unbound allowance is shared"
    );
    // One of the bound uid's two requests this minute, so a refusal below
    // comes from the unbound allowance, not its own.
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
    g.admin_ok(json!({ "op": "delete", "id": id }));
    assert_eq!(
        g.send(AGENT, "nope", ping()),
        Some(refused(Value::Null)),
        "unbound once its credential is deleted"
    );

    let mut s = settings();
    s.uid_limits = RequestLimits {
        per_minute: 100_000,
        per_hour: 100_000,
        per_day: 100_000,
    };
    let mut g = Gw::with(s);
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    for uid in 10_000..12_000 {
        g.send(uid, "nope", ping());
    }
    assert!(
        g.send(AGENT, &token, ping())
            .unwrap()
            .get("result")
            .is_some(),
        "thousands of unbound uids do not fill the tracker"
    );
}

/// A credential over its audit budget is frozen and served nothing, not even
/// a ping; unfreezing restores its budget.
#[test]
fn a_credential_over_its_audit_budget_is_served_nothing_until_unfrozen() {
    let mut s = settings();
    s.audit_budgets = (3, u32::MAX);
    let mut g = Gw::with(s);
    let (id, token) = g.issue(&nostr_grant(g.key), AGENT);
    for _ in 0..3 {
        assert!(!g.tool(&token, "get_nostr_pubkey", json!({})).1);
    }
    let over = g.rpc(&token, "tools/call", json!({ "name": "get_nostr_pubkey" }));
    assert_eq!(over["error"]["code"], json!(-32603), "{over}");
    assert_eq!(g.send(AGENT, &token, ping()), Some(refused(json!(1))));
    let listed = g.admin_ok(json!({ "op": "list" }));
    assert_eq!(listed[0]["frozen"], json!(true), "{listed}");
    g.admin_ok(json!({ "op": "unfreeze", "id": id }));
    assert!(g.rpc(&token, "ping", json!({})).get("result").is_some());
    assert!(!g.tool(&token, "get_nostr_pubkey", json!({})).1);
}

/// Stopping writes out open refusal counts and refusals still deferred.
#[test]
fn stopping_writes_out_refusal_counts_and_deferred_refusals() {
    let mut g = Gw::new();
    let (id, token) = g.issue(&nostr_grant(g.key), AGENT);
    for _ in 0..2 {
        assert!(
            g.tool(
                &token,
                "sign_nostr_event",
                json!({ "kind": 4, "content": "" })
            )
            .1
        );
    }
    assert_eq!(g.send(OTHER, &token, ping()), Some(refused(json!(1))));
    g.state.shut_down();
    let reasons = g.reasons(AuditEventType::AgentRefused);
    assert!(
        reasons
            .iter()
            .any(|r| r.starts_with(&format!("agent {id} denied x1 more since"))),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&format!(
            "agent {id} unauthenticated \"presented by uid {OTHER}\""
        )),
        "{reasons:?}"
    );
}

/// The uids credentials are bound to are read back at start.
#[test]
fn bound_uids_are_known_again_after_a_restart() {
    let mut g = Gw::new();
    let (_, token) = g.issue(&nostr_grant(g.key), AGENT);
    let mut g = g.restart(BOOT, T0).unwrap();
    let per_minute = settings().uid_limits.per_minute;
    for uid in 0..per_minute {
        g.send(20_000 + uid, "nope", ping());
    }
    assert_eq!(g.send(30_000, "nope", ping()), Some(refused(Value::Null)));
    assert!(g
        .send(AGENT, &token, ping())
        .unwrap()
        .get("result")
        .is_some());
}

/// Journal lines for refused requests are written on the tick, never before
/// the answer, once a minute per uid.
#[test]
fn journal_lines_wait_for_the_tick() {
    let mut g = Gw::new();
    g.send(5_000, "nope", ping());
    g.send(5_000, "nope", ping());
    g.send(5_001, "nope", ping());
    assert_eq!(g.state.journal_lines(), 2, "once a minute per uid");
    g.state.tick();
    assert_eq!(g.state.journal_lines(), 0);
    g.send(5_000, "nope", ping());
    assert_eq!(g.state.journal_lines(), 0, "not again this minute");
    for uid in 10_000..12_000 {
        g.send(uid, "nope", ping());
    }
    assert!(
        g.state.journal_lines() < 1_024,
        "at most so many uids a minute"
    );
}
