// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `ssh_sign` through the gateway: what an agent is shown of an SSH key,
//! what it gets signed, what is refused, and what the audit log keeps.

use base64::Engine;
use keep_core::audit::AuditEventType;
use keep_core::secret::{SecretKind, SecretRecord};
use serde_json::{json, Value};

use super::tests::{store_secret, Gw, AGENT};
use crate::ssh::wire::put_string;
use crate::ssh::{parse_host_key, public_key_text, ED25519};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const SESSION: &[u8] = &[0x5a; 32];
const REFUSED: &str = "denied: request not allowed";

/// An SSH server's host key: an Ed25519 key signs as a host's does.
struct Host {
    key: crate::ssh::SshKey,
    blob: Vec<u8>,
}

fn host(seed: u8) -> Host {
    let key = crate::ssh::SshKey::from_bytes(&[seed; 32]).unwrap();
    let blob = key.public_blob();
    Host { key, blob }
}

impl Host {
    fn binding(&self, forwarding: u8) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, &self.blob);
        put_string(&mut b, SESSION);
        put_string(&mut b, &self.key.sign(SESSION));
        b.push(forwarding);
        b
    }

    fn text(&self) -> String {
        public_key_text(&self.blob).unwrap()
    }
}

fn login(user: &str, key: &[u8], host: &Host) -> Vec<u8> {
    let mut d = Vec::new();
    put_string(&mut d, SESSION);
    d.push(50);
    put_string(&mut d, user.as_bytes());
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey-hostbound-v00@openssh.com");
    d.push(1);
    put_string(&mut d, ED25519.as_bytes());
    put_string(&mut d, key);
    put_string(&mut d, &host.blob);
    d
}

fn sshsig(namespace: &str) -> Vec<u8> {
    let mut d = b"SSHSIG".to_vec();
    put_string(&mut d, namespace.as_bytes());
    put_string(&mut d, b"");
    put_string(&mut d, b"sha512");
    put_string(&mut d, &[1u8; 64]);
    d
}

fn store_ssh_key(g: &mut Gw, name: &str) -> [u8; 32] {
    let (_, seed) = crate::ssh::SshKey::generate().unwrap();
    let record = SecretRecord::new(name.into(), SecretKind::SshKey, seed.to_vec()).unwrap();
    g.state.keep_mut().store_secret(&record).unwrap();
    record.id
}

fn ssh_entry(secret: &[u8; 32], host: &Host) -> Value {
    json!({
        "secret": hex::encode(secret),
        "ssh": {
            "users": ["git"],
            "host_keys": [host.text()],
            "sshsig_namespaces": ["git"]
        }
    })
}

fn ssh_grant(entries: Vec<Value>) -> Value {
    json!({
        "keys": [],
        "operations": ["ssh_sign"],
        "event_kinds": [],
        "nip44_peers": [],
        "bitcoin": null,
        "secrets": entries,
    })
}

fn issue(g: &mut Gw, grant: Value) -> Value {
    g.admin(json!({ "op": "issue", "name": "pusher", "uid": AGENT, "grant": grant }))
}

/// A gateway with an SSH key granted for logins to `host` as `git`, and
/// SSHSIG in `git`: its token, the key's id and its public encoding.
fn granted(g: &mut Gw, host: &Host) -> (String, [u8; 32], Vec<u8>) {
    let id = store_ssh_key(g, "deploy key");
    let answer = issue(g, ssh_grant(vec![ssh_entry(&id, host)]));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let token = answer["token"].as_str().unwrap().to_string();
    let (listed, err) = g.tool(&token, "list_secrets", json!({}));
    assert!(!err, "{listed}");
    let key = parse_host_key(listed["secrets"][0]["public_key"].as_str().unwrap()).unwrap();
    (token, id, key)
}

fn sign(
    g: &mut Gw,
    token: &str,
    id: &[u8; 32],
    data: &[u8],
    bindings: &[Vec<u8>],
) -> (Value, bool) {
    let bindings: Vec<String> = bindings.iter().map(|b| B64.encode(b)).collect();
    g.tool(
        token,
        "ssh_sign",
        json!({ "secret": hex::encode(id), "data": B64.encode(data), "flags": 0, "bindings": bindings }),
    )
}

fn verifies(key: &[u8], data: &[u8], answer: &Value) -> bool {
    let sig = B64.decode(answer["signature"].as_str().unwrap()).unwrap();
    crate::ssh::host_signed(key, &sig, data)
}

#[test]
fn an_agent_sees_its_ssh_key_by_public_key_and_tool() {
    let mut g = Gw::new();
    let h = host(1);
    let (token, id, key) = granted(&mut g, &h);
    let (listed, _) = g.tool(&token, "list_secrets", json!({}));
    let entry = &listed["secrets"][0];
    assert_eq!(entry["id"], json!(hex::encode(id)));
    assert_eq!(entry["kind"], json!("ssh_key"));
    assert_eq!(entry["usable"], json!(true));
    assert_eq!(entry["ssh"]["users"], json!(["git"]));
    assert!(entry.get("http").is_none());
    assert_eq!(key.len(), 51);
    let list = g.rpc(&token, "tools/list", json!({}));
    let mut names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["get_session_info", "list_secrets", "ssh_sign"]);
}

#[test]
fn a_login_and_an_sshsig_are_signed_and_recorded() {
    let mut g = Gw::new();
    let h = host(1);
    let (token, id, key) = granted(&mut g, &h);
    let data = login("git", &key, &h);
    let (answer, err) = sign(&mut g, &token, &id, &data, &[h.binding(0)]);
    assert!(!err, "{answer}");
    assert!(verifies(&key, &data, &answer));
    let data = sshsig("git");
    let (answer, err) = sign(&mut g, &token, &id, &data, &[]);
    assert!(!err, "{answer}");
    assert!(verifies(&key, &data, &answer));
    let served: Vec<String> = g
        .reasons(AuditEventType::AgentServed)
        .into_iter()
        .filter(|r| r.contains("ssh_sign"))
        .collect();
    let fingerprint = crate::ssh::fingerprint(&h.blob);
    assert!(
        served
            .iter()
            .any(|r| r.contains("login git host") && r.contains(&fingerprint)),
        "{served:?}"
    );
    assert!(
        served.iter().any(|r| r.contains("sshsig git")),
        "{served:?}"
    );
}

#[test]
fn every_refusal_reads_the_same_and_its_reason_is_recorded() {
    let mut g = Gw::new();
    let h = host(1);
    let stranger = host(2);
    let (token, id, key) = granted(&mut g, &h);
    let cases = vec![
        ("root", login("root", &key, &h), vec![h.binding(0)], "user"),
        ("unbound", login("git", &key, &h), vec![], "no SSH session"),
        (
            "forwarded",
            login("git", &key, &h),
            vec![h.binding(1)],
            "forwarding",
        ),
        (
            "stranger",
            login("git", &key, &stranger),
            vec![stranger.binding(0)],
            "host key the rule does not name",
        ),
        ("namespace", sshsig("file"), vec![], "namespace"),
        (
            "sshsig bound",
            sshsig("git"),
            vec![h.binding(0)],
            "bound to an SSH session",
        ),
    ];
    for (what, data, bindings, why) in cases {
        let (answer, err) = sign(&mut g, &token, &id, &data, &bindings);
        assert!(err, "{what}: {answer}");
        assert_eq!(answer, json!(REFUSED), "{what}");
        let reasons = g.reasons(AuditEventType::AgentRefused);
        assert!(
            reasons.iter().any(|r| r.contains(why)),
            "{what}: {reasons:?}"
        );
    }
    let (answer, err) = g.tool(
        &token,
        "ssh_sign",
        json!({ "secret": hex::encode(id), "data": B64.encode(sshsig("git")), "flags": 2 }),
    );
    assert!(err && answer == json!(REFUSED), "flags: {answer}");
    let other = store_ssh_key(&mut g, "other key");
    let (answer, err) = sign(&mut g, &token, &other, &sshsig("git"), &[]);
    assert!(err && answer == json!(REFUSED), "ungranted key: {answer}");
}

#[test]
fn arguments_are_checked_before_anything_else() {
    let mut g = Gw::new();
    let h = host(1);
    let (token, id, _) = granted(&mut g, &h);
    let secret = hex::encode(id);
    for args in [
        json!({ "secret": secret }),
        json!({ "secret": secret, "data": "%%" }),
        json!({ "secret": secret, "data": B64.encode(vec![0u8; 16 * 1024 + 1]) }),
        json!({ "secret": secret, "data": "", "bindings": ["", "", "", "", ""] }),
        json!({ "secret": secret, "data": "", "bindings": "x" }),
        json!({ "secret": secret, "data": "", "flags": -1 }),
        json!({ "secret": secret, "data": "", "other": 1 }),
        json!({ "secret": "zz", "data": "" }),
    ] {
        let answer = g.rpc(
            &token,
            "tools/call",
            json!({ "name": "ssh_sign", "arguments": args }),
        );
        assert!(answer["error"].is_object(), "{args}: {answer}");
    }
}

#[test]
fn issue_pairs_ssh_rules_with_ssh_keys_and_ssh_sign() {
    let mut g = Gw::new();
    let h = host(1);
    let ssh_key = store_ssh_key(&mut g, "deploy key");
    let token = store_secret(&mut g, "api token", SecretKind::ApiToken);
    let http_entry = json!({
        "secret": hex::encode(ssh_key),
        "http": [{
            "host": "api.example.com", "port": 443, "methods": ["GET"],
            "path_prefix": "/v1", "header": "authorization", "format": "Bearer {}"
        }]
    });
    let mut http_grant = ssh_grant(vec![http_entry]);
    http_grant["operations"] = json!(["http_request"]);
    let mut no_op = ssh_grant(vec![ssh_entry(&ssh_key, &h)]);
    no_op["operations"] = json!(["http_request"]);
    let mut both = ssh_entry(&ssh_key, &h);
    both["http"] = json!([{
        "host": "api.example.com", "port": 443, "methods": ["GET"],
        "path_prefix": "/v1", "header": "authorization", "format": "Bearer {}"
    }]);
    let mut bad_host = ssh_entry(&ssh_key, &h);
    bad_host["ssh"]["host_keys"] = json!([format!("{} comment", h.text())]);
    let answer = issue(&mut g, ssh_grant(vec![ssh_entry(&token, &h)]));
    assert!(
        answer["error"]
            .as_str()
            .unwrap_or_default()
            .contains("an SSH rule is for an ssh_key"),
        "{answer}"
    );
    for (what, grant) in [
        ("an ssh key sent over http", http_grant),
        ("ssh rule without ssh_sign", no_op),
        ("ssh_sign without ssh rules", {
            let mut g = ssh_grant(vec![]);
            g["operations"] = json!(["ssh_sign"]);
            g
        }),
        ("both uses", ssh_grant(vec![both])),
        ("host key with a comment", ssh_grant(vec![bad_host])),
    ] {
        let answer = issue(&mut g, grant);
        assert!(answer["error"].is_string(), "{what}: {answer}");
    }
    assert!(g.state.keep().agent_credentials().unwrap().is_empty());
}

#[test]
fn an_ssh_key_that_does_not_hold_a_seed_is_refused_at_issue() {
    let mut g = Gw::new();
    let h = host(1);
    let record = SecretRecord::new("short".into(), SecretKind::SshKey, vec![1u8; 31]).unwrap();
    g.state.keep_mut().store_secret(&record).unwrap();
    let answer = issue(&mut g, ssh_grant(vec![ssh_entry(&record.id, &h)]));
    assert!(
        answer["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not an SSH key keep generated"),
        "{answer}"
    );
}

#[test]
fn ssh_sign_with_a_secret_sent_over_http_is_refused() {
    let mut g = Gw::new();
    let h = host(1);
    let ssh_key = store_ssh_key(&mut g, "deploy key");
    let api = store_secret(&mut g, "api token", SecretKind::ApiToken);
    let mut entries = vec![
        ssh_entry(&ssh_key, &h),
        json!({
            "secret": hex::encode(api),
            "http": [{
                "host": "api.example.com", "port": 443, "methods": ["GET"],
                "path_prefix": "/v1", "header": "authorization", "format": "Bearer {}"
            }]
        }),
    ];
    entries.sort_by_key(|e| e["secret"].as_str().unwrap().to_string());
    let mut grant = ssh_grant(entries);
    grant["operations"] = json!(["http_request", "ssh_sign"]);
    let answer = issue(&mut g, grant);
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let token = answer["token"].as_str().unwrap().to_string();
    let (answer, err) = sign(&mut g, &token, &api, &sshsig("git"), &[]);
    assert!(err && answer == json!(REFUSED), "{answer}");
    let reasons = g.reasons(AuditEventType::AgentRefused);
    assert!(
        reasons.iter().any(|r| r.contains("not an SSH key")),
        "{reasons:?}"
    );
}
