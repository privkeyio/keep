// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use super::*;

fn ed25519_host() -> (ed25519_dalek::SigningKey, Vec<u8>) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut blob = Vec::new();
    put_string(&mut blob, ED25519.as_bytes());
    put_string(&mut blob, key.verifying_key().as_bytes());
    (key, blob)
}

fn p256_host() -> (p256::ecdsa::SigningKey, Vec<u8>) {
    let key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let mut blob = Vec::new();
    put_string(&mut blob, ECDSA_P256.as_bytes());
    put_string(&mut blob, b"nistp256");
    put_string(
        &mut blob,
        key.verifying_key().to_encoded_point(false).as_bytes(),
    );
    (key, blob)
}

fn ed25519_sig(key: &ed25519_dalek::SigningKey, data: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut sig = Vec::new();
    put_string(&mut sig, ED25519.as_bytes());
    put_string(&mut sig, &key.sign(data).to_bytes());
    sig
}

fn mpint(bytes: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        [&[0u8][..], &trimmed].concat()
    } else {
        trimmed
    }
}

fn p256_sig(key: &p256::ecdsa::SigningKey, data: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = key.sign(data);
    let mut inner = Vec::new();
    put_string(&mut inner, &mpint(&sig.r().to_bytes()));
    put_string(&mut inner, &mpint(&sig.s().to_bytes()));
    let mut out = Vec::new();
    put_string(&mut out, ECDSA_P256.as_bytes());
    put_string(&mut out, &inner);
    out
}

const SESSION: &[u8] = &[0x5a; 32];

fn binding(host: &[u8], session: &[u8], sig: &[u8], forwarding: u8) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, host);
    put_string(&mut b, session);
    put_string(&mut b, sig);
    b.push(forwarding);
    b
}

struct Login<'a> {
    session: &'a [u8],
    user: &'a str,
    service: &'a str,
    method: &'a [u8],
    has_signature: u8,
    alg: &'a str,
    key: &'a [u8],
    bound_host: Option<&'a [u8]>,
}

fn login_data(l: &Login<'_>) -> Vec<u8> {
    let mut d = Vec::new();
    put_string(&mut d, l.session);
    d.push(50);
    put_string(&mut d, l.user.as_bytes());
    put_string(&mut d, l.service.as_bytes());
    put_string(&mut d, l.method);
    d.push(l.has_signature);
    put_string(&mut d, l.alg.as_bytes());
    put_string(&mut d, l.key);
    if let Some(h) = l.bound_host {
        put_string(&mut d, h);
    }
    d
}

fn rule(host: &[u8]) -> SshRule {
    SshRule {
        users: vec!["deploy".into(), "git".into()],
        host_keys: vec![public_key_text(host).unwrap()],
        sshsig_namespaces: vec!["git".into()],
    }
}

fn agent_key() -> SshKey {
    SshKey::from_bytes(&[3u8; 32]).unwrap()
}

#[test]
fn a_key_signs_as_ssh_ed25519_and_reads_back() {
    let key = agent_key();
    let blob = key.public_blob();
    assert_eq!(key_type(&blob), Some(ED25519));
    let text = public_key_text(&blob).unwrap();
    assert!(
        text.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"),
        "{text}"
    );
    assert_eq!(parse_host_key(&text), Some(blob.clone()));
    let sig = key.sign(b"data");
    assert!(host_signed(&blob, &sig, b"data"));
    assert!(!host_signed(&blob, &sig, b"other"));
    assert!(SshKey::from_bytes(&[0u8; 31]).is_none());
    let (generated, seed) = SshKey::generate().unwrap();
    assert_eq!(
        SshKey::from_bytes(&*seed).unwrap().public_blob(),
        generated.public_blob()
    );
}

#[test]
fn fingerprints_read_as_openssh_prints_them_and_a_change_accepts_them() {
    let (_, host) = ed25519_host();
    let label = host_key_label(&host).unwrap();
    assert!(label.starts_with("ssh-ed25519 SHA256:"), "{label}");
    assert!(keep_approval::change::ssh_host_key_ok(&label));
    let (_, p256) = p256_host();
    assert!(keep_approval::change::ssh_host_key_ok(
        &host_key_label(&p256).unwrap()
    ));
}

#[test]
fn host_keys_parse_only_in_known_hosts_form() {
    let (_, host) = ed25519_host();
    let text = public_key_text(&host).unwrap();
    assert!(parse_host_key(&text).is_some());
    let (_, p256) = p256_host();
    assert!(parse_host_key(&public_key_text(&p256).unwrap()).is_some());
    let encoded = STANDARD.encode(&host);
    // A nistp256 key's encoding ends in padding, after a character with
    // spare bits: setting one makes another string of the same bytes.
    let p256_text = public_key_text(&p256).unwrap();
    let (kind, b64) = p256_text.split_once(' ').unwrap();
    let body = b64.trim_end_matches('=');
    let last = body.as_bytes()[body.len() - 1];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let next = alphabet[alphabet.iter().position(|&c| c == last).unwrap() + 1] as char;
    let stray = format!(
        "{kind} {}{next}{}",
        &body[..body.len() - 1],
        &b64[body.len()..]
    );
    assert!(parse_host_key(&stray).is_none(), "stray bits");
    assert!(
        parse_host_key(&format!("{kind} {body}")).is_none(),
        "no padding"
    );
    for bad in [
        format!("{text} comment"),
        format!("{text}\n"),
        format!(" {text}"),
        format!("ssh-ed25519  {encoded}"),
        format!("ecdsa-sha2-nistp256 {encoded}"),
        format!("ssh-rsa {encoded}"),
        format!("SSH-ED25519 {encoded}"),
        format!("ssh-ed25519 {}", &encoded[..encoded.len() - 4]),
        "ssh-ed25519".into(),
    ] {
        assert!(parse_host_key(&bad).is_none(), "{bad:?}");
    }
    // Not a point on the curve.
    let mut off_curve = Vec::new();
    put_string(&mut off_curve, ECDSA_P256.as_bytes());
    put_string(&mut off_curve, b"nistp256");
    put_string(&mut off_curve, &[[4u8].as_slice(), &[1u8; 64]].concat());
    assert_eq!(key_type(&off_curve), None);
    // Compressed, which OpenSSH never writes.
    let (key, _) = p256_host();
    let mut compressed = Vec::new();
    put_string(&mut compressed, ECDSA_P256.as_bytes());
    put_string(&mut compressed, b"nistp256");
    put_string(
        &mut compressed,
        key.verifying_key().to_encoded_point(true).as_bytes(),
    );
    assert_eq!(key_type(&compressed), None);
    let mut trailing = host.clone();
    trailing.push(0);
    assert_eq!(key_type(&trailing), None);
}

#[test]
fn rules_validate() {
    let (_, host) = ed25519_host();
    assert!(rule(&host).validate().is_ok());
    let only_sshsig = SshRule {
        users: vec![],
        host_keys: vec![],
        sshsig_namespaces: vec!["file".into()],
    };
    assert!(only_sshsig.validate().is_ok());
    let mut bad = Vec::new();
    let mut r = rule(&host);
    r.users = vec!["git".into(), "deploy".into()];
    bad.push(r);
    let mut r = rule(&host);
    r.users = vec![];
    bad.push(r);
    let mut r = rule(&host);
    r.host_keys = vec![];
    bad.push(r);
    bad.push(SshRule {
        users: vec![],
        host_keys: vec![],
        sshsig_namespaces: vec![],
    });
    let mut r = rule(&host);
    r.users = vec!["-oProxyCommand".into()];
    bad.push(r);
    let mut r = rule(&host);
    r.users = vec!["a b".into()];
    bad.push(r);
    let mut r = rule(&host);
    r.sshsig_namespaces = vec![String::new()];
    bad.push(r);
    let mut r = rule(&host);
    r.host_keys = vec![format!("{} host", public_key_text(&host).unwrap())];
    bad.push(r);
    let mut r = rule(&host);
    r.users = (0..=MAX_SSH_ITEMS).map(|i| format!("u{i:02}")).collect();
    bad.push(r);
    for r in bad {
        assert!(r.validate().is_err(), "{r:?}");
    }
}

#[test]
fn a_rule_is_shown_to_an_approver_by_fingerprint() {
    let (_, a) = ed25519_host();
    let (_, b) = p256_host();
    let mut r = rule(&a);
    r.host_keys = vec![public_key_text(&a).unwrap(), public_key_text(&b).unwrap()];
    r.host_keys.sort();
    let change = r.change();
    let mut want = vec![host_key_label(&a).unwrap(), host_key_label(&b).unwrap()];
    want.sort();
    assert_eq!(change.host_keys, want);
    assert_eq!(change.users, r.users);
}

fn good_login<'a>(key: &'a [u8], host: &'a [u8], hostbound: bool) -> Login<'a> {
    Login {
        session: SESSION,
        user: "git",
        service: "ssh-connection",
        method: if hostbound {
            PUBLICKEY_HOSTBOUND
        } else {
            b"publickey"
        },
        has_signature: 1,
        alg: ED25519,
        key,
        bound_host: hostbound.then_some(host),
    }
}

#[test]
fn a_login_in_a_session_a_granted_host_signed_is_signed() {
    let (host_key, host) = ed25519_host();
    let key = agent_key().public_blob();
    let bound = vec![binding(&host, SESSION, &ed25519_sig(&host_key, SESSION), 0)];
    let data = login_data(&good_login(&key, &host, true));
    assert_eq!(
        check_request(&rule(&host), &key, &data, &bound),
        Ok(Signing::Login {
            user: "git",
            host: host.clone()
        })
    );
    // A plain publickey login names no server: a granted host's key, in the
    // wrong hands, could bind any server's session to itself.
    let plain = login_data(&good_login(&key, &host, false));
    assert!(check_request(&rule(&host), &key, &plain, &bound).is_err());
    // A nistp256 host key, as many servers have, and its signature over
    // anything else refused.
    let (p_key, p_host) = p256_host();
    let bound = vec![binding(&p_host, SESSION, &p256_sig(&p_key, SESSION), 0)];
    let data = login_data(&good_login(&key, &p_host, true));
    assert!(check_request(&rule(&p_host), &key, &data, &bound).is_ok());
    let wrong = vec![binding(&p_host, SESSION, &p256_sig(&p_key, b"other"), 0)];
    assert!(check_request(&rule(&p_host), &key, &data, &wrong).is_err());
}

#[test]
fn every_login_check_refuses() {
    let (host_key, host) = ed25519_host();
    let (other_key, other_host) = p256_host();
    let key = agent_key().public_blob();
    let other_agent = SshKey::from_bytes(&[4u8; 32]).unwrap().public_blob();
    let sig = ed25519_sig(&host_key, SESSION);
    let bound = || vec![binding(&host, SESSION, &sig, 0)];
    let good = || good_login(&key, &host, true);
    let r = rule(&host);
    let check = |data: &[u8], bindings: &[Vec<u8>]| check_request(&r, &key, data, bindings).is_ok();
    let data = login_data(&good());

    assert!(!check(&data, &[]), "no binding");
    assert!(
        !check(&data, &[bound()[0].clone(), bound()[0].clone()]),
        "two"
    );
    assert!(
        !check(&data, &[binding(&host, SESSION, &sig, 1)]),
        "forwarded"
    );
    let mut trailing = bound()[0].clone();
    trailing.push(0);
    assert!(!check(&data, &[trailing]), "binding trailing byte");
    assert!(
        !check(
            &data,
            &[binding(&host, SESSION, &ed25519_sig(&host_key, b"x"), 0)]
        ),
        "host signed something else"
    );
    assert!(
        !check(
            &data,
            &[binding(&host, SESSION, &p256_sig(&other_key, SESSION), 0)]
        ),
        "another key's signature"
    );
    let other_bound = vec![binding(
        &other_host,
        SESSION,
        &p256_sig(&other_key, SESSION),
        0,
    )];
    let data_other = login_data(&good_login(&key, &other_host, true));
    assert!(!check(&data_other, &other_bound), "host not granted");
    let long = vec![0u8; 33];
    assert!(
        !check(
            &data,
            &[binding(&host, &long, &ed25519_sig(&host_key, &long), 0)]
        ),
        "session id of no hash length"
    );

    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let other_session = [0x5bu8; 32];
    cases.push((
        "other session",
        login_data(&Login {
            session: &other_session,
            ..good()
        }),
    ));
    cases.push((
        "user",
        login_data(&Login {
            user: "root",
            ..good()
        }),
    ));
    cases.push((
        "service",
        login_data(&Login {
            service: "ssh-userauth",
            ..good()
        }),
    ));
    cases.push((
        "method",
        login_data(&Login {
            method: b"hostbased",
            bound_host: None,
            ..good()
        }),
    ));
    cases.push((
        "no signature",
        login_data(&Login {
            has_signature: 0,
            ..good()
        }),
    ));
    cases.push((
        "alg",
        login_data(&Login {
            alg: "rsa-sha2-256",
            ..good()
        }),
    ));
    cases.push((
        "other key",
        login_data(&Login {
            key: &other_agent,
            ..good()
        }),
    ));
    cases.push((
        "bound host",
        login_data(&Login {
            bound_host: Some(&other_host),
            ..good()
        }),
    ));
    let mut extra = data.clone();
    extra.push(0);
    cases.push(("trailing", extra));
    let mut msg = data.clone();
    msg[4 + SESSION.len()] = 51;
    cases.push(("message type", msg));
    cases.push(("truncated", data[..data.len() - 1].to_vec()));
    cases.push(("empty", Vec::new()));
    for (what, d) in cases {
        assert!(!check(&d, &bound()), "{what}");
    }
    assert!(check(&data, &bound()));
}

fn sshsig(namespace: &str, reserved: &[u8], alg: &str, hash: &[u8]) -> Vec<u8> {
    let mut d = SSHSIG_MAGIC.to_vec();
    put_string(&mut d, namespace.as_bytes());
    put_string(&mut d, reserved);
    put_string(&mut d, alg.as_bytes());
    put_string(&mut d, hash);
    d
}

#[test]
fn an_sshsig_in_a_granted_namespace_on_an_unbound_connection_is_signed() {
    let (host_key, host) = ed25519_host();
    let key = agent_key().public_blob();
    let r = rule(&host);
    for (alg, len) in [("sha256", 32), ("sha512", 64)] {
        let data = sshsig("git", b"", alg, &vec![1u8; len]);
        assert_eq!(
            check_request(&r, &key, &data, &[]),
            Ok(Signing::Sshsig { namespace: "git" })
        );
    }
    let good = sshsig("git", b"", "sha512", &[1u8; 64]);
    let bound = vec![binding(&host, SESSION, &ed25519_sig(&host_key, SESSION), 0)];
    assert!(check_request(&r, &key, &good, &bound).is_err(), "bound");
    let mut trailing = good.clone();
    trailing.push(0);
    for (what, data) in [
        ("namespace", sshsig("file", b"", "sha512", &[1u8; 64])),
        ("reserved", sshsig("git", b"x", "sha512", &[1u8; 64])),
        ("alg", sshsig("git", b"", "sha1", &[1u8; 20])),
        ("hash length", sshsig("git", b"", "sha256", &[1u8; 64])),
        ("trailing", trailing),
        ("truncated", good[..good.len() - 1].to_vec()),
    ] {
        assert!(check_request(&r, &key, &data, &[]).is_err(), "{what}");
    }
}

#[test]
fn mpints_read_positive_and_minimal() {
    assert_eq!(
        mpint32(&[1]),
        Some({
            let mut a = [0u8; 32];
            a[31] = 1;
            a
        })
    );
    assert!(mpint32(&[0, 0x80]).is_some());
    assert!(mpint32(&[0x80]).is_none(), "negative");
    assert!(mpint32(&[0, 1]).is_none(), "not minimal");
    assert!(mpint32(&[]).is_none());
    assert!(mpint32(&[1u8; 33]).is_none());
    assert!(mpint32(&[[0u8].as_slice(), &[0xffu8; 32]].concat()).is_some());
}

#[test]
fn a_high_s_host_signature_still_verifies() {
    // OpenSSH hosts do not normalize s, so refusing a high s would refuse
    // half of all logins to nistp256 hosts.
    use p256::elliptic_curve::scalar::IsHigh;
    let (key, host) = p256_host();
    let sig: p256::ecdsa::Signature = {
        use p256::ecdsa::signature::Signer;
        key.sign(SESSION)
    };
    let (r, s) = sig.split_scalars();
    let high_s = if bool::from(s.is_high()) { *s } else { -*s };
    let mut inner = Vec::new();
    put_string(&mut inner, &mpint(&r.to_bytes()));
    put_string(&mut inner, &mpint(&high_s.to_bytes()));
    let mut blob = Vec::new();
    put_string(&mut blob, ECDSA_P256.as_bytes());
    put_string(&mut blob, &inner);
    assert!(host_signed(&host, &blob, SESSION));
}

#[test]
fn only_a_host_bound_login_of_a_hash_length_session_is_signed() {
    let (host_key, host) = ed25519_host();
    let key = agent_key().public_blob();
    let r = rule(&host);
    // Plain publickey, even with the host key appended as the host-bound
    // method carries it.
    let bound = vec![binding(&host, SESSION, &ed25519_sig(&host_key, SESSION), 0)];
    let plain = login_data(&Login {
        method: b"publickey",
        ..good_login(&key, &host, true)
    });
    assert!(check_request(&r, &key, &plain, &bound).is_err());
    for len in [20, 32, 48, 64] {
        let session = vec![7u8; len];
        let bound = vec![binding(
            &host,
            &session,
            &ed25519_sig(&host_key, &session),
            0,
        )];
        let data = login_data(&Login {
            session: &session,
            ..good_login(&key, &host, true)
        });
        assert!(check_request(&r, &key, &data, &bound).is_ok(), "{len}");
    }
    for len in [1, 19, 33, 65, 128] {
        let session = vec![7u8; len];
        let bound = vec![binding(
            &host,
            &session,
            &ed25519_sig(&host_key, &session),
            0,
        )];
        let data = login_data(&Login {
            session: &session,
            ..good_login(&key, &host, true)
        });
        assert!(check_request(&r, &key, &data, &bound).is_err(), "{len}");
    }
}

#[test]
fn a_host_signature_must_be_exactly_its_own_kind() {
    use ed25519_dalek::Signer;
    let (host_key, host) = ed25519_host();
    let raw = host_key.sign(SESSION).to_bytes();
    let mut relabeled = Vec::new();
    put_string(&mut relabeled, ECDSA_P256.as_bytes());
    put_string(&mut relabeled, &raw);
    assert!(
        !host_signed(&host, &relabeled, SESSION),
        "another kind's label"
    );
    let mut trailing = ed25519_sig(&host_key, SESSION);
    trailing.push(0);
    assert!(!host_signed(&host, &trailing, SESSION), "trailing byte");

    let (p_key, p_host) = p256_host();
    let good = p256_sig(&p_key, SESSION);
    assert!(host_signed(&p_host, &good, SESSION));
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(!host_signed(&p_host, &trailing, SESSION), "trailing byte");
    // A byte after s, inside the signature's own string.
    let mut r = Reader::new(&good);
    r.string().unwrap();
    let mut inner = r.string().unwrap().to_vec();
    inner.push(0);
    let mut padded = Vec::new();
    put_string(&mut padded, ECDSA_P256.as_bytes());
    put_string(&mut padded, &inner);
    assert!(
        !host_signed(&p_host, &padded, SESSION),
        "trailing byte inside"
    );
}

#[test]
fn host_keys_must_be_sorted() {
    let (_, a) = ed25519_host();
    let (_, b) = p256_host();
    let mut keys = vec![public_key_text(&a).unwrap(), public_key_text(&b).unwrap()];
    keys.sort();
    let mut r = rule(&a);
    r.host_keys = keys.clone();
    assert!(r.validate().is_ok());
    keys.reverse();
    r.host_keys = keys;
    assert!(r.validate().is_err());
}
