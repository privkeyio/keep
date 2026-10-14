// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use super::*;
use crate::gateway::bridge::testing::{me, patient, token, Fake, Peer};

const TOKEN: &str = "keep_agt_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const KEY_ID: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn key_blob() -> Vec<u8> {
    crate::ssh::SshKey::from_seed(&[3u8; 32])
        .unwrap()
        .public_blob()
}

fn result(content: Value, is_error: bool) -> Value {
    json!({ "isError": is_error, "content": [{ "type": "text", "text": content.to_string() }] })
}

/// A gateway that lists one usable SSH key (and an HTTP secret and an
/// unusable key, which are not offered), and signs anything but data
/// `"refuse"` with the signature `sig`.
fn gateway() -> Fake {
    Fake::start(|mut peer: Peer| {
        while let Some(envelope) = peer.next() {
            let message = &envelope["message"];
            let answer = match message["params"]["name"].as_str() {
                Some("list_secrets") => result(
                    json!({ "secrets": [
                        { "id": KEY_ID, "name": "deploy key", "kind": "ssh_key", "usable": true,
                          "public_key": crate::ssh::public_key_text(&key_blob()).unwrap() },
                        { "id": "44".repeat(32), "name": "token", "kind": "api_token", "usable": true },
                        { "id": "55".repeat(32), "name": "gone", "kind": "ssh_key", "usable": false },
                    ]}),
                    false,
                ),
                Some("ssh_sign") => {
                    let refuse = message["params"]["arguments"]["data"] == B64.encode("refuse");
                    if refuse {
                        result(json!("denied: request not allowed"), true)
                    } else {
                        result(json!({ "signature": B64.encode("sig") }), false)
                    }
                }
                _ => result(json!("unknown tool"), true),
            };
            peer.reply(&json!({ "jsonrpc": "2.0", "id": message["id"], "result": answer }));
        }
    })
}

fn agent(fake: &Fake) -> SshAgent {
    SshAgent::new(Bridge::connect(&fake.path, me(), token(TOKEN), patient()).unwrap())
}

fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut m = vec![SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut m, blob);
    put_string(&mut m, data);
    m.extend_from_slice(&flags.to_be_bytes());
    m
}

fn session_bind(binding: &[u8]) -> Vec<u8> {
    let mut m = vec![SSH_AGENTC_EXTENSION];
    put_string(&mut m, SESSION_BIND);
    m.extend_from_slice(binding);
    m
}

fn signs_requested(fake: &Fake) -> Vec<Value> {
    fake.log()
        .into_iter()
        .map(|(_, e)| e["message"].clone())
        .filter(|m| m["params"]["name"] == "ssh_sign")
        .map(|m| m["params"]["arguments"].clone())
        .collect()
}

#[test]
fn only_usable_ssh_keys_are_offered() {
    let fake = gateway();
    let agent = agent(&fake);
    let answer = agent.handle(&mut Connection::default(), &[SSH_AGENTC_REQUEST_IDENTITIES]);
    let mut want = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1];
    put_string(&mut want, &key_blob());
    put_string(&mut want, b"deploy key");
    assert_eq!(answer, want);
    for envelope in fake.log() {
        assert_eq!(envelope.1["token"], json!(TOKEN));
    }
}

#[test]
fn a_signature_request_goes_to_the_gateway_with_the_connections_bindings() {
    let fake = gateway();
    let agent = agent(&fake);
    let mut conn = Connection::default();
    assert_eq!(
        agent.handle(&mut conn, &session_bind(b"binding")),
        [SSH_AGENT_SUCCESS]
    );
    let answer = agent.handle(&mut conn, &sign_request(&key_blob(), b"data", 0));
    let mut want = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut want, b"sig");
    assert_eq!(answer, want);
    let signs = signs_requested(&fake);
    assert_eq!(
        signs,
        [json!({
            "secret": KEY_ID,
            "data": B64.encode("data"),
            "flags": 0,
            "bindings": [B64.encode("binding")],
        })]
    );
    // Bindings belong to their connection.
    let mut other = Connection::default();
    agent.handle(&mut other, &sign_request(&key_blob(), b"data", 0));
    assert_eq!(signs_requested(&fake)[1]["bindings"], json!([]));
}

#[test]
fn anything_refused_or_malformed_is_a_failure() {
    let fake = gateway();
    let agent = agent(&fake);
    let failure = vec![SSH_AGENT_FAILURE];
    let mut conn = Connection::default();
    let mut trailing = sign_request(&key_blob(), b"data", 0);
    trailing.push(0);
    let mut query = vec![SSH_AGENTC_EXTENSION];
    put_string(&mut query, b"query");
    for (what, request) in [
        ("refused", sign_request(&key_blob(), b"refuse", 0)),
        ("unknown key", sign_request(b"not a key", b"data", 0)),
        ("trailing", trailing),
        (
            "truncated",
            sign_request(&key_blob(), b"data", 0)[..10].to_vec(),
        ),
        ("empty", Vec::new()),
        (
            "identities with a body",
            vec![SSH_AGENTC_REQUEST_IDENTITIES, 0],
        ),
        ("add identity", vec![17]),
        ("remove all", vec![19]),
        ("lock", vec![22]),
        ("query", query),
    ] {
        assert_eq!(agent.handle(&mut conn, &request), failure, "{what}");
    }
}

#[test]
fn a_connection_bound_too_often_signs_nothing() {
    let fake = gateway();
    let agent = agent(&fake);
    let mut conn = Connection::default();
    for _ in 0..=MAX_BINDINGS {
        assert_eq!(
            agent.handle(&mut conn, &session_bind(b"b")),
            [SSH_AGENT_SUCCESS]
        );
    }
    assert_eq!(
        agent.handle(&mut conn, &sign_request(&key_blob(), b"data", 0)),
        [SSH_AGENT_FAILURE]
    );
    assert!(signs_requested(&fake).is_empty());
}

#[test]
fn messages_are_framed_and_bounded() {
    let fake = gateway();
    let agent = Arc::new(agent(&fake));
    let (mut client, server) = UnixStream::pair().unwrap();
    let serving = agent.clone();
    let handle = std::thread::spawn(move || serving.serve_connection(server));
    client
        .write_all(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES])
        .unwrap();
    let mut len = [0u8; 4];
    client.read_exact(&mut len).unwrap();
    let mut answer = vec![0u8; u32::from_be_bytes(len) as usize];
    client.read_exact(&mut answer).unwrap();
    assert_eq!(answer[0], SSH_AGENT_IDENTITIES_ANSWER);
    client
        .write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
        .unwrap();
    assert!(
        handle.join().unwrap().is_err(),
        "an oversized message ends it"
    );
    let (mut client, server) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || agent.serve_connection(server));
    client.write_all(&[0, 0, 0, 0]).unwrap();
    assert!(handle.join().unwrap().is_err(), "an empty message ends it");
}

#[test]
fn the_socket_is_made_only_in_a_closed_directory_of_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(listen(&open.join("agent.sock"), me()).is_err());
    let closed = dir.path().join("closed");
    std::fs::create_dir(&closed).unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = closed.join("agent.sock");
    assert!(listen(&path, me() + 1).is_err(), "another owner");
    let first = listen(&path, me()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    drop(first);
    listen(&path, me()).expect("an old socket is replaced");
    let file = closed.join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(listen(&file, me()).is_err(), "a file is never removed");
    assert!(file.exists());
}
