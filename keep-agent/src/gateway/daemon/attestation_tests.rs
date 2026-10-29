// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use super::*;

/// Real chains from Google's Android Key Attestation verifier
/// (android/keyattestation, `testdata/`, Apache-2.0), as devices returned
/// them.
fn vector(name: &str) -> Vec<Vec<u8>> {
    let pem = match name {
        "caiman_tee_rkp" => {
            include_str!("testdata/android_attestation/caiman_sdk36_tee_ec_rkp.pem")
        }
        "caiman_sb_rkp" => include_str!("testdata/android_attestation/caiman_sdk36_sb_ec_rkp.pem"),
        "frankel_2026" => {
            include_str!("testdata/android_attestation/frankel_sdk37_tee_ec_2026.pem")
        }
        "tegu_sb_2026" => {
            include_str!("testdata/android_attestation/tegu_sdk36_sb_ec_2026_root.pem")
        }
        "sony_factory" => {
            include_str!("testdata/android_attestation/sony_xperia10_iii_sdk33_tee_ec.pem")
        }
        "walleye_factory" => {
            include_str!("testdata/android_attestation/walleye_sdk27_tee_ec_none.pem")
        }
        "akita_unlocked" => {
            include_str!("testdata/android_attestation/akita_sdk34_tee_ec_none.pem")
        }
        "marlin_software" => {
            include_str!("testdata/android_attestation/marlin_sdk29_tee_ec_none.pem")
        }
        "bad_locked" => {
            include_str!("testdata/android_attestation/invalid_malformed_rot_device_locked.pem")
        }
        "bad_order" => {
            include_str!("testdata/android_attestation/invalid_tags_not_in_ascending_order.pem")
        }
        "p256_sha384" => include_str!("testdata/android_attestation/p256_sha384_intermediate.pem"),
        _ => unreachable!(),
    };
    Certificate::load_pem_chain(pem.as_bytes())
        .unwrap()
        .iter()
        .map(|c| x509_cert::der::Encode::to_der(c).unwrap())
        .collect()
}

/// Each real chain at the time its key was made: its dates, its version,
/// its security level, its challenge and its boot state, as Google's own
/// parsed copy of it says.
#[test]
fn real_chains_verify_and_parse() {
    let cases: [(&str, u64, u64, u64, &str, u64, bool); 7] = [
        (
            "caiman_tee_rkp",
            1758900680,
            400,
            SECURITY_TEE,
            "64363838643736332d363131382d346361362d393462322d653663643965643765346534",
            BOOT_VERIFIED,
            true,
        ),
        (
            "caiman_sb_rkp",
            1758900646,
            300,
            SECURITY_STRONGBOX,
            "37636361633165612d343834352d343832652d383538642d663666613961613863323935",
            BOOT_VERIFIED,
            true,
        ),
        (
            "frankel_2026",
            1788561021,
            500,
            SECURITY_TEE,
            "65383635326563322d633332312d346133632d623131352d393562353963666636383335",
            BOOT_VERIFIED,
            true,
        ),
        (
            "tegu_sb_2026",
            1771979841,
            300,
            SECURITY_STRONGBOX,
            "39303537386531642d663562662d346363662d613237662d613466346438396565323166",
            BOOT_VERIFIED,
            true,
        ),
        (
            "sony_factory",
            1780585145,
            3,
            SECURITY_TEE,
            "3eafe4d5dd0090de5a42b432b42481af5ce29963656b2584c59a492de16d00c9",
            BOOT_VERIFIED,
            true,
        ),
        (
            "walleye_factory",
            1787857347,
            2,
            SECURITY_TEE,
            "39313238393565302d336531392d343332372d613066622d393165326633663436636462",
            2,
            false,
        ),
        (
            "akita_unlocked",
            1727389885,
            300,
            SECURITY_TEE,
            "6368616c6c656e6765",
            2,
            false,
        ),
    ];
    for (name, made, version, level, challenge, state, locked) in cases {
        let chain = vector(name);
        let verified = verify_chain(&chain, &GOOGLE_ROOTS, made).expect(name);
        assert_eq!(verified.serials.len(), chain.len() - 1, "{name}");
        let record = KeyDescription::parse(&verified.record).expect(name);
        assert_eq!(record.attestation_version, version, "{name}");
        assert_eq!(record.attestation_level, level, "{name}");
        assert_eq!(record.keymint_level, level, "{name}");
        assert_eq!(hex::encode(&record.challenge), challenge, "{name}");
        let hw = &record.hardware;
        assert!(
            hw.purpose.as_ref().unwrap().contains(&PURPOSE_SIGN),
            "{name}"
        );
        assert_eq!(hw.algorithm, Some(ALGORITHM_EC), "{name}");
        assert_eq!(hw.ec_curve, Some(CURVE_P256), "{name}");
        assert_eq!(hw.origin, Some(ORIGIN_GENERATED), "{name}");
        assert!(hw.no_auth_required, "{name}");
        let root = hw.root_of_trust.as_ref().unwrap();
        assert_eq!((root.state, root.locked), (state, locked), "{name}");
        assert!(record.software.application_id.is_some(), "{name}");
    }
}

/// The real chains are refused for what they say: these keys need no
/// authentication, or the device is unlocked, or the format is too old.
#[test]
fn real_chains_are_judged() {
    for (name, made, why) in [
        ("caiman_tee_rkp", 1758900680, "does not need a biometric"),
        ("tegu_sb_2026", 1771979841, "does not need a biometric"),
        ("akita_unlocked", 1727389885, "does not need a biometric"),
        ("walleye_factory", 1787857347, "older than Keymaster 4"),
    ] {
        let verified = verify_chain(&vector(name), &GOOGLE_ROOTS, made).unwrap();
        let record = KeyDescription::parse(&verified.record).unwrap();
        let challenge: [u8; 32] = record.challenge.clone().try_into().unwrap_or([0; 32]);
        let err = if record.challenge.len() == 32 {
            judge(&record, &challenge).unwrap_err()
        } else {
            let mut patched = record;
            patched.challenge = vec![0; 32];
            judge(&patched, &[0; 32]).unwrap_err()
        };
        assert!(err.contains(why), "{name}: {err}");
    }
}

#[test]
fn real_chains_are_refused_out_of_date() {
    // Remote provisioning certificates are short lived, so expiry counts.
    let chain = vector("caiman_tee_rkp");
    let err = verify_chain(&chain, &GOOGLE_ROOTS, 1758900680 + 400 * 86400)
        .err()
        .unwrap();
    assert!(err.contains("expired"), "{err}");
    let err = verify_chain(&chain, &GOOGLE_ROOTS, 1_600_000_000)
        .err()
        .unwrap();
    assert!(err.contains("not valid yet"), "{err}");
    // A factory chain's keys cannot be rotated, so its expiry is not held
    // against it.
    assert!(verify_chain(&vector("sony_factory"), &GOOGLE_ROOTS, 4_000_000_000).is_ok());
}

#[test]
fn only_a_google_root_is_trusted() {
    let err = verify_chain(&vector("marlin_software"), &GOOGLE_ROOTS, 1572308512)
        .err()
        .unwrap();
    assert!(err.contains("Google attestation root"), "{err}");
    // The new P-384 root signs real chains.
    assert!(verify_chain(&vector("frankel_2026"), &GOOGLE_ROOTS[..1], 1788561021).is_err());
}

#[test]
fn a_p256_key_signing_with_sha384_verifies() {
    let chain = vector("p256_sha384");
    let certs: Vec<_> = chain
        .iter()
        .map(|d| Certificate::from_der(d).unwrap())
        .collect();
    check_signature(&chain[0], &certs[0], &certs[1]).unwrap();
    check_signature(&chain[1], &certs[1], &certs[2]).unwrap();
    check_signature(&chain[2], &certs[2], &certs[2]).unwrap();
    assert!(check_signature(&chain[0], &certs[0], &certs[2]).is_err());
}

#[test]
fn google_malformed_records_are_refused() {
    for name in ["bad_locked", "bad_order"] {
        let chain = vector(name);
        let leaf = Certificate::from_der(&chain[0]).unwrap();
        let record = leaf
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id == KEY_DESCRIPTION)
            .unwrap()
            .extn_value
            .as_bytes()
            .to_vec();
        assert!(KeyDescription::parse(&record).is_err(), "{name}");
    }
}

#[test]
fn serials_are_written_as_google_lists_them() {
    assert_eq!(serial_hex(&[0x00, 0x2c, 0x8c, 0xdd]), "2c8cdd");
    assert_eq!(serial_hex(&[0x0a]), "a");
    assert_eq!(serial_hex(&[0x00]), "0");
}

#[test]
fn der_is_read_strictly() {
    assert_eq!(unsigned(&[0x00]), Ok(0));
    assert_eq!(unsigned(&[0x00, 0x80]), Ok(0x80));
    assert_eq!(unsigned(&[0x00, 0xff, 0xff, 0xff, 0xff]), Ok(0xffff_ffff));
    for bad in [&[][..], &[0x80], &[0x00, 0x01], &[0x01; 9]] {
        assert!(unsigned(bad).is_err(), "{bad:?}");
    }
    // A long length that fits the short form, an indefinite length, and a
    // long tag number that fits the short form.
    for bad in [
        &[0x04, 0x81, 0x01, 0x00][..],
        &[0x30, 0x80, 0x00, 0x00],
        &[0xbf, 0x1e, 0x00],
    ] {
        assert!(Der::new(bad).read().is_err(), "{bad:?}");
    }
    let t = Der::new(&[0xbf, 0x85, 0x45, 0x00]).read().unwrap();
    assert_eq!((t.class, t.constructed, t.number), (CONTEXT, true, 709));
}

// Minted chains, under the test root only test builds trust.

use keep_approval::test_attestation::{self as minted, Intermediate, Record, NOW};

const CHALLENGE: [u8; 32] = [0x5a; 32];

struct Minted {
    chain: Vec<Vec<u8>>,
    approver: [u8; 33],
}

fn approver_key() -> [u8; 33] {
    minted::key(3)
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn mint_with(record: &Record, intermediate: Intermediate) -> Minted {
    let approver = approver_key();
    Minted {
        chain: minted::mint(&approver, record, intermediate).0,
        approver,
    }
}

fn mint(record: &Record) -> Minted {
    mint_with(record, Intermediate::default())
}

fn good() -> Record {
    Record::new(&CHALLENGE)
}

fn check(m: &Minted) -> Result<Attested, String> {
    verify(&m.chain, &CHALLENGE, &m.approver, NOW)
}

#[test]
fn test_builds_trust_the_test_root_and_releases_do_not() {
    assert_eq!(TEST_ROOT, minted::root_key_hash());
    assert!(trusted_roots().contains(&TEST_ROOT));
    let m = mint(&good());
    assert!(check(&m).is_ok());
    let err = verify_with(&m.chain, &GOOGLE_ROOTS, &CHALLENGE, &m.approver, NOW).unwrap_err();
    assert!(err.contains("Google attestation root"), "{err}");
}

#[test]
fn a_well_made_approver_key_is_taken() {
    assert_eq!(
        check(&mint(&good())).unwrap(),
        Attested {
            serials: vec!["3".into(), "2c8c".into()],
            strongbox: false,
            grapheneos: false,
        }
    );
    let strongbox = Record {
        level: SECURITY_STRONGBOX,
        keymint_level: SECURITY_STRONGBOX,
        purposes: vec![PURPOSE_SIGN, PURPOSE_VERIFY],
        user_auth_type: Some(AUTH_FINGERPRINT | 4),
        ..good()
    };
    assert!(check(&mint(&strongbox)).unwrap().strongbox);
    let grapheneos = Record {
        boot_state: BOOT_SELF_SIGNED,
        boot_key: hex::decode(GRAPHENEOS_BOOT_KEYS[8]).unwrap(),
        ..good()
    };
    assert!(check(&mint(&grapheneos)).unwrap().grapheneos);
}

/// Each rule, broken alone, refuses the key, with the reason it gives.
#[test]
fn each_rule_refuses_the_key() {
    let d = good();
    let cases: Vec<(Record, &str)> = vec![
        (
            Record {
                version: 2,
                ..d.clone()
            },
            "older than Keymaster 4",
        ),
        (
            Record {
                level: 0,
                keymint_level: 0,
                ..d.clone()
            },
            "secure hardware",
        ),
        (
            Record {
                keymint_level: SECURITY_STRONGBOX,
                ..d.clone()
            },
            "secure hardware",
        ),
        (
            Record {
                challenge: vec![0x5b; 32],
                ..d.clone()
            },
            "another pairing",
        ),
        (
            Record {
                purposes: vec![PURPOSE_VERIFY],
                ..d.clone()
            },
            "only a signing key",
        ),
        (
            Record {
                purposes: vec![PURPOSE_SIGN, 0],
                ..d.clone()
            },
            "only a signing key",
        ),
        (
            Record {
                algorithm: 1,
                ..d.clone()
            },
            "not a P-256 key",
        ),
        (
            Record {
                curve: 2,
                ..d.clone()
            },
            "not a P-256 key",
        ),
        (
            Record {
                origin: 2,
                ..d.clone()
            },
            "not generated",
        ),
        (
            Record {
                no_auth_required: true,
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                no_auth_required_in_software: true,
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                user_auth_type: None,
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                user_auth_type: Some(AUTH_PASSWORD),
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                user_auth_type: Some(AUTH_PASSWORD | AUTH_FINGERPRINT),
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                auth_timeout: Some(0),
                ..d.clone()
            },
            "biometric for every use",
        ),
        (
            Record {
                root_of_trust: false,
                ..d.clone()
            },
            "no root of trust",
        ),
        (
            Record {
                locked: false,
                ..d.clone()
            },
            "unlocked",
        ),
        (
            Record {
                boot_state: 2,
                ..d.clone()
            },
            "verified OS",
        ),
        (
            Record {
                boot_state: BOOT_SELF_SIGNED,
                ..d.clone()
            },
            "verified OS",
        ),
        (
            Record {
                packages: vec!["com.example.other"],
                ..d.clone()
            },
            "Keep app",
        ),
        (
            Record {
                packages: vec![APP_PACKAGE, "com.example.other"],
                ..d.clone()
            },
            "Keep app",
        ),
        (
            Record {
                signers: vec![vec![0x3e; 32]],
                ..d.clone()
            },
            "Keep app",
        ),
        (
            Record {
                signers: vec![hex::decode(APP_SIGNER).unwrap(), vec![0; 32]],
                ..d.clone()
            },
            "Keep app",
        ),
    ];
    for (record, why) in cases {
        let err = check(&mint(&record)).unwrap_err();
        assert!(err.contains(why), "{why}: {err}");
    }
}

#[test]
fn the_attested_key_must_be_the_approver_key() {
    let mut m = mint(&good());
    m.approver = minted::key(9)
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(check(&m).unwrap_err().contains("not the approver key"));
}

#[test]
fn the_chain_must_hold_together() {
    let m = mint(&good());

    let short = Minted {
        chain: m.chain[1..].to_vec(),
        approver: m.approver,
    };
    assert!(check(&short).unwrap_err().contains("3 to 5"));
    let long = Minted {
        chain: vec![m.chain[0].clone(); 6],
        approver: m.approver,
    };
    assert!(check(&long).unwrap_err().contains("3 to 5"));

    // A leaf from another session under the same intermediate verifies, but
    // its record is for another pairing.
    let other = mint(&Record {
        challenge: vec![1; 32],
        ..good()
    });
    let swapped = Minted {
        chain: vec![
            other.chain[0].clone(),
            m.chain[1].clone(),
            m.chain[2].clone(),
        ],
        approver: m.approver,
    };
    assert!(check(&swapped).unwrap_err().contains("another pairing"));

    // A tampered leaf no longer verifies.
    let mut tampered = mint(&good());
    let at = tampered.chain[0].len() / 2;
    tampered.chain[0][at] ^= 1;
    assert!(check(&tampered).is_err());

    // A certificate below the leaf, signed by the attested key itself, with
    // a record of its own: only the first record can be trusted.
    let mut extra = mint(&good());
    let below = minted::cert(
        4,
        &minted::name("Appended", false),
        &minted::spki(&minted::key(4)),
        &minted::name("Android Keystore Key", false),
        &minted::key(3),
        (0, NOW),
        Some(&good().der()),
    );
    extra.chain.insert(0, below);
    assert!(check(&extra).unwrap_err().contains("outside the leaf"));

    // An issuer that is not the next certificate's subject.
    let mut renamed = mint(&good());
    renamed.chain[1] = minted::cert(
        0x2c8c,
        &minted::name("Someone Else", false),
        &minted::spki(&minted::key(0xa2)),
        &minted::name("Test Root", false),
        &minted::key(0xa1),
        (NOW - 10, NOW + 10),
        None,
    );
    assert!(check(&renamed).unwrap_err().contains("another issuer"));
}

#[test]
fn intermediate_dates_count_unless_the_chain_is_from_the_factory() {
    let dates = |not_before, not_after, factory| Intermediate {
        not_before,
        not_after,
        factory,
    };
    let expired = mint_with(&good(), dates(NOW - 100, NOW - 1, false));
    assert!(check(&expired).unwrap_err().contains("expired"));
    let early = mint_with(&good(), dates(NOW + 1, NOW + 100, false));
    assert!(check(&early).unwrap_err().contains("not valid yet"));
    assert!(check(&mint_with(&good(), dates(NOW - 100, NOW - 1, true))).is_ok());
    let factory_early = mint_with(&good(), dates(NOW + 1, NOW + 100, true));
    assert!(check(&factory_early).unwrap_err().contains("not valid yet"));
}

#[test]
fn a_status_list_names_what_is_revoked_or_suspended() {
    let list = br#"{"entries": {
        "2c8cdddfd5e03bfc": {"status": "REVOKED", "expires": "2020-11-13", "reason": "KEY_COMPROMISE"},
        "00C8966FCB2FBE32": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"},
        "6681152659205225093": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
        "9999999999999999999999999999999999999999999999999": {"status": "REVOKED"},
        "a": {"status": "SOMETHING_NEW"}
    }}"#;
    let unusable = unusable_serials(list).unwrap();
    assert_eq!(unusable.len(), 6);
    assert!(unusable.contains("2c8cdddfd5e03bfc"));
    assert!(unusable.contains("c8966fcb2fbe32"));
    // Google writes some serials in decimal.
    assert!(unusable.contains("5cb838f1fe157a85"));
    assert!(unusable.contains("6681152659205225093"));
    assert!(unusable.contains("6d79f82328ea3da61e066ebb2f889ffffffffffff"));
    for bad in [
        &b"{}"[..],
        b"[]",
        b"{\"entries\": {\"a\": {}}}",
        b"not json",
    ] {
        assert!(
            unusable_serials(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}
