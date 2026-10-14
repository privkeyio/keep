// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Fixed test vectors (`vectors/v1.json`), shared with the approver's own
//! implementation. Every value is recomputed here and compared, the P-256
//! signatures included (RFC 6979 nonces make them deterministic), except
//! the BIP-340 freeze signatures, which use fresh auxiliary randomness and
//! are verified instead.
//!
//! Regenerate with `KEEP_APPROVAL_WRITE_VECTORS=1 cargo test -p keep-approval
//! --test vectors`; a change to any deterministic value is a protocol change.

use bitcoin::absolute::LockTime;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use keep_approval::binding::{
    check_request, Binding, Network, Nip44DecryptPayload, Nip44EncryptPayload, NostrPayload,
    Payload, RequestDraft, UnsignedEventFields,
};
use keep_approval::change::{
    Change, ChangeBitcoin, ChangeGrant, ChangeLimits, ChangeRule, ChangeSecret, ChangeSsh, Decimal,
    Scope,
};
use keep_approval::messages::{
    AnchorState, Budget, CredentialRef, FreezeAction, LogPoint, Reason, Request, SignerKey,
    Verdict, WalletAnchor, WalletName,
};
use keep_approval::psbt::PsbtPayload;
use keep_approval::sig::{self, xonly, ApproverSigningKey};
use keep_approval::wrap::TagKey;
use keep_approval::{Hex16, Hex32, Hex33, Hex64};
use nostr::{Keys, SecretKey};
use serde_json::{json, Value};

fn keys(byte: u8) -> Keys {
    Keys::new(SecretKey::from_slice(&[byte; 32]).unwrap())
}

fn approver_key() -> ApproverSigningKey {
    ApproverSigningKey::from_slice(&[0x03; 32]).unwrap()
}

/// A PSBT spending two taproot inputs, and with `third`, a third input the
/// gateway does not sign: a P2WPKH output with a sighash the signer refuses.
fn psbt(third: bool) -> Psbt {
    let script = |b: u8| {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[b; 32]);
        ScriptBuf::from_bytes(s)
    };
    let inputs = if third { 3u8 } else { 2 };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..inputs)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                        [i + 1; 32],
                    )),
                    vout: u32::from(i),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: script(0xaa),
            },
            TxOut {
                value: Amount::from_sat(15_000),
                script_pubkey: script(0xbb),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(40_000),
        script_pubkey: script(0x01),
    });
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(6_000),
        script_pubkey: script(0x02),
    });
    psbt.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(1));
    if third {
        let mut wpkh = vec![0x00, 0x14];
        wpkh.extend_from_slice(&[0x03; 20]);
        psbt.inputs[2].witness_utxo = Some(TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: ScriptBuf::from_bytes(wpkh),
        });
        psbt.inputs[2].sighash_type = Some(PsbtSighashType::from_u32(0x83));
    }
    psbt
}

fn drafts(key: [u8; 32]) -> Vec<(&'static str, RequestDraft)> {
    let credential = CredentialRef {
        id: Hex16([0x22; 16]),
        name: "writer".into(),
        uid: 1001,
    };
    let anchor = AnchorState {
        seq: 4210,
        head: Hex32([0x33; 32]),
        prev: Some(LogPoint {
            seq: 4170,
            head: Hex32([0x32; 32]),
        }),
        wallets: vec![WalletAnchor {
            wallet: WalletName::new(true, &key),
            seq: 88,
            spent: 40_000,
            window: 100_000,
        }],
    };
    let draft = |payload: Payload, reason, key, network, credential| RequestDraft {
        request_id: [0x44; 32],
        created_at: 1_791_580_000,
        deadline_secs: 120,
        credential,
        key,
        network,
        reason,
        payload,
        budget: None,
        anchor: anchor.clone(),
    };
    let grant = ChangeGrant {
        keys: vec![Hex32(key)],
        operations: vec!["sign_nostr_event".into(), "sign_psbt".into()],
        event_kinds: vec![Decimal(0), Decimal(1)],
        nip44_peers: vec![],
        bitcoin: Some(ChangeBitcoin {
            network: "bitcoin".into(),
            per_psbt_sats: Decimal(50_000),
            window_sats: Decimal(100_000),
            approval_above_sats: Some(Decimal(20_000)),
            address_allowlist: None,
        }),
        limits: ChangeLimits {
            per_minute: Decimal(10),
            per_hour: Decimal(100),
            per_day: Decimal(1000),
        },
        secrets: vec![],
    };
    let secrets_grant = ChangeGrant {
        keys: vec![],
        operations: vec!["http_request".into()],
        event_kinds: vec![],
        nip44_peers: vec![],
        bitcoin: None,
        limits: ChangeLimits {
            per_minute: Decimal(10),
            per_hour: Decimal(100),
            per_day: Decimal(1000),
        },
        secrets: vec![
            ChangeSecret {
                secret: Hex32([0x31; 32]),
                name: "GitHub token \u{1f511}".into(),
                kind: "api_token".into(),
                http: vec![
                    ChangeRule {
                        host: "api.github.com".into(),
                        port: Decimal(443),
                        path_prefix: "/repos/privkeyio/".into(),
                        methods: vec!["GET".into(), "POST".into()],
                        header: "authorization".into(),
                        format: "Bearer {}".into(),
                        agent_headers: vec!["x-github-api-version".into()],
                    },
                    ChangeRule {
                        host: "xn--bcher-kva.example".into(),
                        port: Decimal(8443),
                        path_prefix: "/v1".into(),
                        methods: vec!["GET".into()],
                        header: "x-api-key".into(),
                        format: "{}".into(),
                        agent_headers: vec![],
                    },
                ],
                ssh: None,
            },
            ChangeSecret {
                secret: Hex32([0x32; 32]),
                name: "Stripe".into(),
                kind: "password".into(),
                http: vec![ChangeRule {
                    host: "api.stripe.com".into(),
                    port: Decimal(443),
                    path_prefix: "/v1/charges".into(),
                    methods: vec!["GET".into()],
                    header: "authorization".into(),
                    format: "Basic {}".into(),
                    agent_headers: vec![],
                }],
                ssh: None,
            },
        ],
    };
    let ssh_grant = ChangeGrant {
        keys: vec![],
        operations: vec!["ssh_sign".into()],
        event_kinds: vec![],
        nip44_peers: vec![],
        bitcoin: None,
        limits: ChangeLimits {
            per_minute: Decimal(10),
            per_hour: Decimal(100),
            per_day: Decimal(1000),
        },
        secrets: vec![ChangeSecret {
            secret: Hex32([0x33; 32]),
            name: "deploy key".into(),
            kind: "ssh_key".into(),
            http: vec![],
            ssh: Some(ChangeSsh {
                users: vec!["deploy".into(), "git".into()],
                host_keys: vec![
                    "ecdsa-sha2-nistp256 SHA256:hpR9FK9WdJ/XhGhFjMPJh24iLQSzfd3mQ0e3F3a5to8".into(),
                    "ssh-ed25519 SHA256:wVHjkspS1XP0W53oSvTloX9wH8Unch9YZOLuVqgFza0".into(),
                ],
                sshsig_namespaces: vec!["git".into()],
            }),
        }],
    };
    vec![
        (
            "sign_nostr_event kind 0",
            draft(
                Payload::Nostr(NostrPayload {
                    event: UnsignedEventFields {
                        pubkey: Hex32(key),
                        created_at: 1_791_580_000,
                        kind: 0,
                        tags: vec![vec!["p".into(), "aa".repeat(32)]],
                        content: "{\"name\":\"agent\"}".into(),
                    },
                }),
                Reason::Kind { kind: 0 },
                Some(key),
                None,
                Some(credential.clone()),
            ),
        ),
        (
            "sign_nostr_event with control, separator and astral characters",
            draft(
                Payload::Nostr(NostrPayload {
                    event: UnsignedEventFields {
                        pubkey: Hex32(key),
                        created_at: 1_791_580_000,
                        kind: 0,
                        tags: vec![vec![
                            "t".into(),
                            "a\u{1}b\u{1f}c\u{7f}\u{2028}d\u{1f600}".into(),
                        ]],
                        content: "\"q\"\\\n\t\u{0}\u{8}\u{c}\u{2028}\u{2029}\u{1f600}\u{10ffff}é"
                            .into(),
                    },
                }),
                Reason::Kind { kind: 0 },
                Some(key),
                None,
                Some(credential.clone()),
            ),
        ),
        ("sign_psbt above threshold", {
            let mut d = draft(
                Payload::Psbt(
                    PsbtPayload::from_psbt(&psbt(false), &[0, 1], &[(1, 7)], Network::Mainnet)
                        .unwrap(),
                ),
                Reason::AboveThreshold {
                    requested: 31_000,
                    spent: 10_000,
                    threshold: 20_000,
                },
                Some(key),
                Some(Network::Mainnet),
                Some(credential.clone()),
            );
            d.budget = Some(Budget {
                credential_spent: 10_000,
                credential_window: 100_000,
                wallet_spent: 40_000,
                wallet_window: 100_000,
            });
            d
        }),
        ("sign_psbt with an input the gateway does not sign", {
            let mut d = draft(
                Payload::Psbt(
                    PsbtPayload::from_psbt(&psbt(true), &[0, 1], &[(1, 7)], Network::Mainnet)
                        .unwrap(),
                ),
                Reason::AboveThreshold {
                    requested: 33_000,
                    spent: 10_000,
                    threshold: 20_000,
                },
                Some(key),
                Some(Network::Mainnet),
                Some(credential.clone()),
            );
            d.budget = Some(Budget {
                credential_spent: 10_000,
                credential_window: 100_000,
                wallet_spent: 40_000,
                wallet_window: 100_000,
            });
            d
        }),
        (
            "nip44_encrypt to own key",
            draft(
                Payload::Nip44Encrypt(Nip44EncryptPayload {
                    peer: Hex32(key),
                    plaintext: "note to self".into(),
                }),
                Reason::EncryptToOwnKey,
                Some(key),
                None,
                Some(credential.clone()),
            ),
        ),
        (
            "nip44_decrypt own payload",
            draft(
                Payload::Nip44Decrypt(Nip44DecryptPayload {
                    peer: Hex32(key),
                    ciphertext_sha256: Hex32([0x55; 32]),
                    plaintext: "{\"token\":\"cashuA...\"}".into(),
                }),
                Reason::DecryptOwnPayload,
                Some(key),
                None,
                Some(credential.clone()),
            ),
        ),
        (
            "management issue_credential",
            draft(
                Payload::Management(Change::IssueCredential {
                    id: Hex16([0x22; 16]),
                    name: "writer".into(),
                    uid: Decimal(1001),
                    created_at: Decimal(1_791_580_000),
                    expires_at: Decimal(1_794_172_000),
                    grant,
                }),
                Reason::Management,
                None,
                None,
                Some(credential.clone()),
            ),
        ),
        (
            "management issue_credential with secrets",
            draft(
                Payload::Management(Change::IssueCredential {
                    id: Hex16([0x23; 16]),
                    name: "deployer".into(),
                    uid: Decimal(1002),
                    created_at: Decimal(1_791_580_000),
                    expires_at: Decimal(1_794_172_000),
                    grant: secrets_grant,
                }),
                Reason::Management,
                None,
                None,
                Some(CredentialRef {
                    id: Hex16([0x23; 16]),
                    name: "deployer".into(),
                    uid: 1002,
                }),
            ),
        ),
        (
            "management issue_credential with an SSH key",
            draft(
                Payload::Management(Change::IssueCredential {
                    id: Hex16([0x24; 16]),
                    name: "git pusher".into(),
                    uid: Decimal(1003),
                    created_at: Decimal(1_791_580_000),
                    expires_at: Decimal(1_794_172_000),
                    grant: ssh_grant,
                }),
                Reason::Management,
                None,
                None,
                Some(CredentialRef {
                    id: Hex16([0x24; 16]),
                    name: "git pusher".into(),
                    uid: 1003,
                }),
            ),
        ),
        (
            "management unfreeze all",
            draft(
                Payload::Management(Change::Unfreeze {
                    scope: Scope::All,
                    epoch: Decimal(41),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
        ),
        (
            "management unfreeze one credential",
            draft(
                Payload::Management(Change::Unfreeze {
                    scope: Scope::Credential(Hex16([0x22; 16])),
                    epoch: Decimal(41),
                }),
                Reason::Management,
                None,
                None,
                Some(credential.clone()),
            ),
        ),
        (
            "management add_approver",
            draft(
                Payload::Management(Change::AddApprover {
                    transport: Hex32([0x66; 32]),
                    approver: Hex33(sig::approver_key(&approver_key())),
                    label: "Kyle\u{2019}s téléphone \u{1f4f1}".into(),
                    fingerprint: sig::fingerprint(&[0x66; 32], &sig::approver_key(&approver_key())),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
        ),
        (
            "management remove_approver",
            draft(
                Payload::Management(Change::RemoveApprover {
                    transport: Hex32([0x66; 32]),
                    approver: Hex33(sig::approver_key(&approver_key())),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
        ),
    ]
}

/// Every vector, with fresh BIP-340 signatures.
fn vectors() -> Value {
    let channel = keys(0x01);
    let transport = keys(0x02);
    let approver = approver_key();
    let vault_key = xonly(&keys(0x04));
    let c = xonly(&channel);
    let t = xonly(&transport);
    let a = sig::approver_key(&approver);

    let mut requests = Vec::new();
    let mut changes = Vec::new();
    for (name, draft) in drafts(vault_key) {
        let binding = Binding {
            channel: c,
            credential: draft.credential.as_ref().map(|c| c.id.0),
            request_id: draft.request_id,
            key: draft.key,
            network: draft.network,
            payload: &draft.payload,
        };
        let preimage = binding.preimage().unwrap();
        if let Payload::Management(change) = &draft.payload {
            changes.push(json!({
                "change": change.to_value(),
                "type_code": change.type_code(),
                "canonical": String::from_utf8(change.canonical()).unwrap(),
                "sha256": hex::encode(change.digest()),
            }));
        }
        let mut extra = json!({});
        match &draft.payload {
            Payload::Nostr(p) => {
                extra["event_id"] = hex::encode(p.event.event_id().unwrap()).into()
            }
            Payload::Psbt(p) => {
                extra["txid"] = p.check(Network::Mainnet).unwrap().txid.into();
            }
            _ => {}
        }
        let (request, hash) = draft.finish(&c).unwrap();
        let mut item = json!({
            "name": name,
            "request": serde_json::to_value(&request).unwrap(),
            "preimage": hex::encode(preimage),
            "request_hash": hex::encode(hash),
        });
        for (k, v) in extra.as_object().unwrap() {
            item[k] = v.clone();
        }
        requests.push(item);
    }

    let hash = Hex32([0x5a; 32]);
    let decisions: Vec<Value> = [Verdict::Approve, Verdict::Deny]
        .into_iter()
        .map(|verdict| {
            let digest = sig::decision_digest(&c, &a, &hash.0, verdict);
            let decision = sig::decision(&approver, &c, Hex32([0x44; 32]), hash, verdict);
            json!({
                "request_hash": hash,
                "decision": verdict,
                "signer": hex::encode(a),
                "digest": hex::encode(digest),
                "sig": decision.sig,
            })
        })
        .collect();
    let scopes = [Scope::All, Scope::Credential(Hex16([0x22; 16]))];
    let mut freezes: Vec<Value> = Vec::new();
    for scope in scopes {
        let f = sig::freeze(&transport, &c, 17, 41, scope);
        freezes.push(json!({
            "action": FreezeAction::Freeze,
            "scope": scope,
            "counter": 17,
            "epoch": 41,
            "signer": f.signer,
            "digest": hex::encode(sig::freeze_digest(&c, &f.signer, 17, 41, FreezeAction::Freeze, scope)),
            "sig": f.sig,
        }));
    }
    for scope in scopes {
        let f = sig::unfreeze(&approver, &c, 17, 41, scope);
        freezes.push(json!({
            "action": FreezeAction::Unfreeze,
            "scope": scope,
            "counter": 17,
            "epoch": 41,
            "signer": f.signer,
            "digest": hex::encode(sig::freeze_digest(&c, &f.signer, 17, 41, FreezeAction::Unfreeze, scope)),
            "sig": f.sig,
        }));
    }
    let secret = [0x07u8; 32];
    let pair_digest = sig::pair_approver_digest(&c, &t, &a);
    let pair = sig::pair(&t, &approver, &c, &secret, "My phone");
    let pairing = json!({
        "secret": hex::encode(secret),
        "proof": sig::pair_proof(&secret, &c, &t, &a),
        "fingerprint": sig::fingerprint(&t, &a),
        "approver_digest": hex::encode(pair_digest),
        "approver_sig": sig::sign_p256(&approver, &pair_digest),
        "message": serde_json::to_value(&pair).unwrap(),
    });
    let wrap_pubkey = xonly(&keys(0x08));
    let content = "AjNkZXNjcmlwdGlvbg==";
    let wrap_tags = json!([
        {
            "between": "channel key to transport key",
            "direction": 1,
            "wrap_pubkey": hex::encode(wrap_pubkey),
            "content": content,
            "tag": hex::encode(TagKey::gateway(&channel, &t).unwrap().tag(&wrap_pubkey, content)),
        },
        {
            "between": "transport key to channel key",
            "direction": 2,
            "wrap_pubkey": hex::encode(wrap_pubkey),
            "content": content,
            "tag": hex::encode(TagKey::device(&transport, &c).unwrap().tag(&wrap_pubkey, content)),
        },
        {
            "between": "pairing secret, phone to gateway",
            "direction": 2,
            "secret": hex::encode(secret),
            "wrap_pubkey": hex::encode(wrap_pubkey),
            "content": content,
            "tag": hex::encode(TagKey::pairing_phone(&secret).tag(&wrap_pubkey, content)),
        }
    ]);
    json!({
        "protocol_version": 1,
        "keys": {
            "channel_secret": hex::encode([0x01u8; 32]),
            "channel": hex::encode(c),
            "transport_secret": hex::encode([0x02u8; 32]),
            "transport": hex::encode(t),
            "approver_alg": "p256",
            "approver_secret": hex::encode([0x03u8; 32]),
            "approver": hex::encode(a),
            "vault_key": hex::encode(vault_key),
        },
        "requests": requests,
        "changes": changes,
        "decisions": decisions,
        "freezes": freezes,
        "pairing": pairing,
        "wrap_tags": wrap_tags,
    })
}

/// The vectors with the BIP-340 signatures removed, for comparing.
fn without_bip340_sigs(mut v: Value) -> Value {
    for item in v["freezes"].as_array_mut().unwrap() {
        if item["action"] == "freeze" {
            item.as_object_mut().unwrap().remove("sig");
        }
    }
    v
}

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1.json")
}

#[test]
fn vectors_match() {
    let fresh = vectors();
    if std::env::var_os("KEEP_APPROVAL_WRITE_VECTORS").is_some() {
        let text = serde_json::to_string_pretty(&fresh).unwrap() + "\n";
        std::fs::write(path(), text).unwrap();
        panic!("vectors written; run again without KEEP_APPROVAL_WRITE_VECTORS to check them");
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(
        without_bip340_sigs(stored.clone()),
        without_bip340_sigs(fresh),
        "a deterministic vector changed"
    );

    // The stored signatures verify, each under its own key and digest only.
    let hex32 = |v: &Value| -> [u8; 32] { Hex32::parse(v.as_str().unwrap()).unwrap().0 };
    let hex33 = |v: &Value| -> [u8; 33] { Hex33::parse(v.as_str().unwrap()).unwrap().0 };
    let hex64 = |v: &Value| Hex64::parse(v.as_str().unwrap()).unwrap();
    for item in stored["decisions"].as_array().unwrap() {
        let (signer, digest, s) = (
            hex33(&item["signer"]),
            hex32(&item["digest"]),
            hex64(&item["sig"]),
        );
        sig::verify_p256(&signer, &digest, &s).unwrap();
        let mut other = digest;
        other[0] ^= 1;
        assert!(sig::verify_p256(&signer, &other, &s).is_err());
    }
    for item in stored["freezes"].as_array().unwrap() {
        let digest = hex32(&item["digest"]);
        let s = hex64(&item["sig"]);
        let signer: SignerKey = serde_json::from_value(item["signer"].clone()).unwrap();
        let mut other = digest;
        other[0] ^= 1;
        match signer {
            SignerKey::Transport(k) => {
                assert_eq!(item["action"], "freeze");
                sig::verify_bip340(&k.0, &digest, &s).unwrap();
                assert!(sig::verify_bip340(&k.0, &other, &s).is_err());
            }
            SignerKey::Approver(k) => {
                assert_eq!(item["action"], "unfreeze");
                sig::verify_p256(&k.0, &digest, &s).unwrap();
                assert!(sig::verify_p256(&k.0, &other, &s).is_err());
            }
        }
    }
    let p = &stored["pairing"];
    let a = hex33(&stored["keys"]["approver"]);
    sig::verify_p256(
        &a,
        &hex32(&p["approver_digest"]),
        &hex64(&p["approver_sig"]),
    )
    .unwrap();

    // Every stored request checks out from its JSON alone, with its event
    // id and txid recomputed.
    let channel = hex32(&stored["keys"]["channel"]);
    for item in stored["requests"].as_array().unwrap() {
        let request: Request =
            keep_approval::messages::parse(&item["request"].to_string()).unwrap();
        let checked = check_request(&request, &channel).unwrap();
        assert_eq!(
            request.request_hash.to_hex(),
            item["request_hash"].as_str().unwrap()
        );
        if let Payload::Nostr(p) = &checked.payload {
            assert_eq!(
                hex::encode(p.event.event_id().unwrap()),
                item["event_id"].as_str().unwrap()
            );
        }
        if let Some(view) = checked.psbt {
            assert_eq!(view.txid, item["txid"].as_str().unwrap());
        }
    }
}
