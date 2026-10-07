// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Adversarial PSBTs against the single-key signer: garbage scripts, forged
//! origins, every sighash value, paths outside the layout, and a seeded mutation
//! loop checking that every signature produced verifies under a wallet key.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::{Input, Psbt, PsbtSighashType};
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{Signature as TaprootSignature, TapLeafHash, TapNodeHash};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use keep_bitcoin::bitcoin;
use keep_bitcoin::{BitcoinSigner, PsbtSigner};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Instant;

const SECRET: [u8; 32] = [7u8; 32];

fn secp() -> &'static Secp256k1<All> {
    static S: OnceLock<Secp256k1<All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

fn signer(net: Network) -> PsbtSigner {
    let mut s = SECRET;
    PsbtSigner::new(&mut s, net).unwrap()
}

fn btc_signer(net: Network) -> BitcoinSigner {
    let mut s = SECRET;
    BitcoinSigner::new(&mut s, net).unwrap()
}

fn master() -> Xpriv {
    Xpriv::new_master(Network::Bitcoin, &SECRET).unwrap()
}

fn fp() -> Fingerprint {
    master().fingerprint(secp())
}

fn path(s: &str) -> DerivationPath {
    DerivationPath::from_str(s).unwrap()
}

fn child_key(p: &DerivationPath) -> XOnlyPublicKey {
    master()
        .derive_priv(secp(), p)
        .unwrap()
        .to_keypair(secp())
        .x_only_public_key()
        .0
}

fn tweaked(key: XOnlyPublicKey) -> XOnlyPublicKey {
    key.tap_tweak(secp(), None).0.to_x_only_public_key()
}

fn bip86_spk(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr(secp(), key, None)
}

fn key_of(n: u8) -> XOnlyPublicKey {
    Keypair::from_seckey_slice(secp(), &[n; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

fn single_key() -> XOnlyPublicKey {
    key_of(SECRET[0])
}

fn single_spk() -> ScriptBuf {
    bip86_spk(single_key())
}

fn foreign_spk(n: u8) -> ScriptBuf {
    bip86_spk(key_of(n))
}

fn coin(net: Network) -> u32 {
    u32::from(net != Network::Bitcoin)
}

fn outpoint(i: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: i,
    }
}

fn psbt_with(inputs: &[(ScriptBuf, u64)], outputs: &[(ScriptBuf, u64)]) -> Psbt {
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: (0..inputs.len() as u32)
            .map(|i| TxIn {
                previous_output: outpoint(i),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(spk, v)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: spk.clone(),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    for (i, (spk, v)) in inputs.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(*v),
            script_pubkey: spk.clone(),
        });
    }
    psbt
}

fn spend_to_foreign(inputs: &[ScriptBuf]) -> Psbt {
    let ins: Vec<_> = inputs.iter().map(|s| (s.clone(), 50_000)).collect();
    psbt_with(&ins, &[(foreign_spk(2), 1_000)])
}

fn origin_in(psbt: &mut Psbt, i: usize, key: XOnlyPublicKey, f: Fingerprint, p: DerivationPath) {
    psbt.inputs[i].tap_key_origins.insert(key, (vec![], (f, p)));
}

fn origin_out(psbt: &mut Psbt, i: usize, key: XOnlyPublicKey, f: Fingerprint, p: DerivationPath) {
    psbt.outputs[i]
        .tap_key_origins
        .insert(key, (vec![], (f, p)));
}

fn wallet_path_ok(p: &DerivationPath, net: Network) -> bool {
    let c: &[ChildNumber] = p.as_ref();
    c.len() == 5
        && c[0] == ChildNumber::Hardened { index: 86 }
        && c[1] == ChildNumber::Hardened { index: coin(net) }
        && c[2].is_hardened()
        && matches!(c[3], ChildNumber::Normal { index: 0 | 1 })
        && c[4].is_normal()
}

fn change_set(net: Network) -> &'static HashSet<ScriptBuf> {
    static MAIN: OnceLock<HashSet<ScriptBuf>> = OnceLock::new();
    static TEST: OnceLock<HashSet<ScriptBuf>> = OnceLock::new();
    let cell = if net == Network::Bitcoin {
        &MAIN
    } else {
        &TEST
    };
    cell.get_or_init(|| {
        let c = coin(net);
        let acct = master()
            .derive_priv(secp(), &path(&format!("86'/{c}'/0'/1")))
            .unwrap();
        (0..1000)
            .map(|i| {
                let k = acct
                    .derive_priv(secp(), &[ChildNumber::Normal { index: i }])
                    .unwrap()
                    .to_keypair(secp())
                    .x_only_public_key()
                    .0;
                bip86_spk(k)
            })
            .collect()
    })
}

/// Every tap_key_sig present must be DEFAULT/ALL, verify under the spent output key
/// with the BIP-341 key-path sighash, and that output key must be the wallet's:
/// the raw secret tweaked, or a BIP-86 child derived here from the secret at an
/// origin path in the accepted layout. Returns the signed input indices.
fn check_signatures(psbt: &Psbt, net: Network) -> Vec<usize> {
    let mut signed = Vec::new();
    if psbt.inputs.iter().all(|i| i.tap_key_sig.is_none()) {
        return signed;
    }
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("signed psbt lacks a utxo"))
        .collect();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(sig) = input.tap_key_sig else {
            continue;
        };
        assert!(
            matches!(
                sig.sighash_type,
                TapSighashType::Default | TapSighashType::All
            ),
            "input {i}: sighash {:?}",
            sig.sighash_type
        );
        assert!(
            input.tap_merkle_root.is_none(),
            "input {i}: script tree signed"
        );
        let spk = &prevouts[i].script_pubkey;
        assert!(spk.is_p2tr(), "input {i}: signed non-p2tr {spk:?}");
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), sig.sighash_type)
            .unwrap();
        secp()
            .verify_schnorr(
                &sig.signature,
                &Message::from_digest(sighash.to_byte_array()),
                &output_key,
            )
            .unwrap_or_else(|e| panic!("input {i}: signature does not verify: {e}"));
        let member = (net == Network::Bitcoin && output_key == tweaked(single_key()))
            || input.tap_key_origins.values().any(|(leaves, (f, p))| {
                leaves.is_empty()
                    && *f == fp()
                    && wallet_path_ok(p, net)
                    && tweaked(child_key(p)) == output_key
            });
        assert!(member, "input {i}: signed for a key outside the wallet");
        signed.push(i);
    }
    signed
}

fn check_change(psbt: &Psbt, net: Network, s: &PsbtSigner) {
    if let Ok(a) = s.analyze(psbt) {
        for o in &a.outputs {
            if o.is_change {
                assert!(
                    change_set(net).contains(&psbt.unsigned_tx.output[o.index].script_pubkey),
                    "output {} mislabeled change under {net:?}",
                    o.index
                );
            }
        }
    }
}

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    eprintln!("[timing] {label}: {:?}", t.elapsed());
    r
}

fn not_on_curve() -> [u8; 32] {
    (0u8..=255)
        .map(|n| {
            let mut x = [0u8; 32];
            x[31] = n;
            x
        })
        .find(|x| XOnlyPublicKey::from_slice(x).is_err())
        .unwrap()
}

#[test]
fn garbage_scripts_never_sign_or_panic() {
    let p0 = path("86'/1'/0'/0/0");
    let k0 = child_key(&p0);
    let good = bip86_spk(k0);
    let ok_bytes = good.as_bytes()[2..34].to_vec();
    let with = |prefix: &[u8], body: &[u8], suffix: &[u8]| {
        ScriptBuf::from_bytes([prefix, body, suffix].concat())
    };
    let tree_root = TapNodeHash::from_byte_array([5; 32]);
    let cases: Vec<(&str, ScriptBuf)> = vec![
        ("empty", ScriptBuf::new()),
        ("OP_1", ScriptBuf::from_bytes(vec![0x51])),
        (
            "truncated p2tr 33B",
            with(&[0x51, 0x20], &ok_bytes[..31], &[]),
        ),
        (
            "p2tr + trailing byte 35B",
            with(&[0x51, 0x20], &ok_bytes, &[0]),
        ),
        ("v0 push32 34B", with(&[0x00, 0x20], &ok_bytes, &[])),
        ("v2 push32 34B", with(&[0x52, 0x20], &ok_bytes, &[])),
        ("OP_1 push33 35B", with(&[0x51, 0x21], &ok_bytes, &[2])),
        (
            "OP_1 PUSHDATA1 32",
            with(&[0x51, 0x4c, 0x20], &ok_bytes, &[]),
        ),
        ("p2tr x >= p", with(&[0x51, 0x20], &[0xff; 32], &[])),
        (
            "p2tr x off curve",
            with(&[0x51, 0x20], &not_on_curve(), &[]),
        ),
        ("p2tr x = 0", with(&[0x51, 0x20], &[0; 32], &[])),
        (
            "raw untweaked child key",
            with(&[0x51, 0x20], &k0.serialize(), &[]),
        ),
        (
            "raw untweaked single key",
            with(&[0x51, 0x20], &single_key().serialize(), &[]),
        ),
        (
            "child key with a script tree",
            ScriptBuf::new_p2tr(secp(), k0, Some(tree_root)),
        ),
        (
            "single key with a script tree",
            ScriptBuf::new_p2tr(secp(), single_key(), Some(tree_root)),
        ),
        ("OP_RETURN", with(&[0x6a, 0x20], &ok_bytes, &[])),
    ];
    for (label, spk) in cases
        .iter()
        .flat_map(|c| [(Network::Testnet, c.clone()), (Network::Bitcoin, c.clone())])
        .map(|(net, (label, spk))| ((label, net), spk))
    {
        let s = signer(label.1);
        let label = format!("{} on {:?}", label.0, label.1);
        let mut psbt = psbt_with(&[(spk.clone(), 50_000)], &[(spk.clone(), 1_000)]);
        origin_in(&mut psbt, 0, k0, fp(), p0.clone());
        psbt.inputs[0].tap_internal_key = Some(k0);
        origin_out(&mut psbt, 0, k0, fp(), path("86'/1'/0'/1/0"));
        psbt.outputs[0].tap_internal_key = Some(k0);
        let a = s.analyze(&psbt).unwrap();
        assert!(a.signable_inputs.is_empty(), "{label}");
        assert!(!a.outputs[0].is_change, "{label}");
        assert_eq!(s.sign(&mut psbt).unwrap(), 0, "{label}");
        assert!(psbt.inputs[0].tap_key_sig.is_none(), "{label}");
    }
}

#[test]
fn missing_witness_utxo_on_any_input_refuses_everything() {
    for missing in [0usize, 1] {
        let mut psbt = spend_to_foreign(&[single_spk(), foreign_spk(3)]);
        psbt.inputs[missing].witness_utxo = None;
        let s = signer(Network::Bitcoin);
        assert!(s.analyze(&psbt).is_err());
        assert!(s.sign(&mut psbt).is_err());
        assert!(btc_signer(Network::Bitcoin).sign_psbt(&mut psbt).is_err());
        assert!(psbt.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    }
}

#[test]
fn amount_overflow_and_negative_fee_are_refused_before_signing() {
    let s = signer(Network::Bitcoin);
    let b = btc_signer(Network::Bitcoin);
    let cases = [
        (vec![u64::MAX, 1], vec![1_000]),
        (vec![u64::MAX / 2 + 1, u64::MAX / 2 + 1], vec![1_000]),
        (vec![50_000], vec![u64::MAX, 1]),
        (vec![50_000], vec![50_001]),
    ];
    for (ins, outs) in cases {
        let ins: Vec<_> = ins.iter().map(|v| (single_spk(), *v)).collect();
        let outs: Vec<_> = outs.iter().map(|v| (foreign_spk(2), *v)).collect();
        let psbt = psbt_with(&ins, &outs);
        let mut psbt = Psbt::deserialize(&psbt.serialize()).expect("wire roundtrip");
        assert!(s.analyze(&psbt).is_err(), "{ins:?} {outs:?}");
        assert!(b.sign_psbt(&mut psbt).is_err());
        assert!(psbt.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    }
    let mut psbt = psbt_with(&[(single_spk(), u64::MAX)], &[(foreign_spk(2), u64::MAX)]);
    let a = s.analyze(&psbt).unwrap();
    assert_eq!(a.fee_sats, 0);
    assert_eq!(b.sign_psbt(&mut psbt).unwrap(), 1);
    check_signatures(&psbt, Network::Bitcoin);
}

#[test]
fn paths_outside_the_layout_never_sign_even_for_wallet_keys() {
    let s = signer(Network::Testnet);
    let deep: Vec<ChildNumber> = (0..255u32)
        .map(|i| {
            if i % 2 == 0 {
                ChildNumber::Hardened { index: i }
            } else {
                ChildNumber::Normal { index: i }
            }
        })
        .collect();
    let mut deep_prefixed = path("86'/1'/0'/0/0").as_ref().to_vec();
    deep_prefixed.extend((0..250).map(|i| ChildNumber::Normal { index: i }));
    let bad: Vec<DerivationPath> = vec![
        DerivationPath::from(deep),
        DerivationPath::from(deep_prefixed),
        DerivationPath::master(),
        path("86/1'/0'/0/0"),
        path("86'/1/0'/0/0"),
        path("86'/1'/0/0/0"),
        path("86'/1'/0'/0'/0"),
        path("86'/1'/0'/0/0'"),
        path("86'/1'/0'/2/0"),
        path("86'/1'/0'/0"),
        path("86'/1'/0'/0/0/0"),
        path("84'/1'/0'/0/0"),
        path("86'/0'/0'/0/0"),
        path("86'/2147483647'/0'/0/0"),
    ];
    for p in &bad {
        let k = child_key(p);
        let mut psbt = spend_to_foreign(&[bip86_spk(k)]);
        origin_in(&mut psbt, 0, k, fp(), p.clone());
        assert_eq!(s.sign(&mut psbt).unwrap(), 0, "{p}");
        let mut out = psbt_with(&[(single_spk(), 50_000)], &[(bip86_spk(k), 1_000)]);
        origin_out(&mut out, 0, k, fp(), p.clone());
        assert!(!s.analyze(&out).unwrap().outputs[0].is_change, "{p}");
    }
    for p in [
        "86'/1'/0'/0/0",
        "86'/1'/2147483647'/1/2147483647",
        "86'/1'/7'/1/5000",
    ] {
        let p = path(p);
        let k = child_key(&p);
        let mut psbt = spend_to_foreign(&[bip86_spk(k)]);
        origin_in(&mut psbt, 0, k, fp(), p.clone());
        assert_eq!(s.sign(&mut psbt).unwrap(), 1, "{p}");
        assert_eq!(check_signatures(&psbt, Network::Testnet), vec![0]);
    }
}

#[test]
fn origin_key_path_mismatches_and_script_leaves_never_sign() {
    let s = signer(Network::Testnet);
    let p0 = path("86'/1'/0'/0/0");
    let p5 = path("86'/1'/0'/0/5");
    let (k0, k5) = (child_key(&p0), child_key(&p5));
    let mut a = spend_to_foreign(&[bip86_spk(k5)]);
    origin_in(&mut a, 0, k5, fp(), p0.clone());
    assert_eq!(s.sign(&mut a).unwrap(), 0, "key 0/5 claimed at 0/0");
    let mut b = spend_to_foreign(&[bip86_spk(k5)]);
    origin_in(&mut b, 0, k0, fp(), p0.clone());
    assert_eq!(s.sign(&mut b).unwrap(), 0, "origin for another wallet key");
    let mut c = spend_to_foreign(&[bip86_spk(k0)]);
    c.inputs[0]
        .tap_key_origins
        .insert(k0, (vec![TapLeafHash::all_zeros()], (fp(), p0.clone())));
    assert_eq!(s.sign(&mut c).unwrap(), 0, "script-path origin");
    let mut d = psbt_with(
        &[(single_spk(), 50_000)],
        &[(bip86_spk(child_key(&path("86'/1'/0'/1/0"))), 1)],
    );
    d.outputs[0].tap_key_origins.insert(
        child_key(&path("86'/1'/0'/1/0")),
        (
            vec![TapLeafHash::all_zeros()],
            (fp(), path("86'/1'/0'/1/0")),
        ),
    );
    assert!(
        !s.analyze(&d).unwrap().outputs[0].is_change,
        "script-path change origin"
    );
}

#[test]
fn foreign_spk_naming_the_wallet_key_never_signs() {
    let s = signer(Network::Testnet);
    let p0 = path("86'/1'/0'/0/0");
    let k0 = child_key(&p0);
    let mut psbt = spend_to_foreign(&[foreign_spk(3), foreign_spk(4)]);
    psbt.inputs[0].tap_internal_key = Some(single_key());
    psbt.inputs[1].tap_internal_key = Some(k0);
    origin_in(&mut psbt, 0, single_key(), fp(), p0.clone());
    origin_in(&mut psbt, 1, k0, fp(), p0.clone());
    origin_in(&mut psbt, 1, tweaked(k0), fp(), p0);
    assert!(s.analyze(&psbt).unwrap().signable_inputs.is_empty());
    assert_eq!(s.sign(&mut psbt).unwrap(), 0);
}

#[test]
fn script_tree_fields_and_prefilled_fields() {
    let s = signer(Network::Bitcoin);
    let mut psbt = spend_to_foreign(&[single_spk()]);
    psbt.inputs[0].tap_merkle_root = Some(TapNodeHash::from_byte_array([1; 32]));
    assert_eq!(s.sign(&mut psbt).unwrap(), 0, "merkle root set");

    let mut psbt = spend_to_foreign(&[single_spk(), foreign_spk(9)]);
    psbt.inputs[0].tap_internal_key = Some(key_of(9));
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![0x50, 1, 2, 3]]));
    let junk = TaprootSignature::from_slice(&[1u8; 64]).unwrap();
    psbt.inputs[0].tap_key_sig = Some(junk);
    psbt.inputs[1].tap_key_sig = Some(junk);
    psbt.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(0x83));
    let signed = s.sign(&mut psbt).unwrap();
    eprintln!(
        "[info] prefilled: signed={signed} input0 sig replaced={} input1 junk kept={} final_script_witness kept={}",
        psbt.inputs[0].tap_key_sig != Some(junk),
        psbt.inputs[1].tap_key_sig == Some(junk),
        psbt.inputs[0].final_script_witness.is_some()
    );
    assert_eq!(signed, 1);
    assert_ne!(psbt.inputs[0].tap_key_sig, Some(junk));
    psbt.inputs[1].tap_key_sig = None;
    assert_eq!(check_signatures(&psbt, Network::Bitcoin), vec![0]);
}

#[test]
fn every_sighash_value() {
    let s = signer(Network::Bitcoin);
    let values = [
        0u32,
        1,
        2,
        3,
        0x81,
        0x82,
        0x83,
        4,
        0x40,
        0x41,
        0x80,
        0x84,
        0xc1,
        0xff,
        0x100,
        0x101,
        0x181,
        0x1_0001,
        0x8000_0001,
        u32::MAX,
    ];
    for v in values {
        let mut psbt = spend_to_foreign(&[single_spk(), foreign_spk(3)]);
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(v));
        let mut psbt = Psbt::deserialize(&psbt.serialize()).unwrap();
        assert_eq!(psbt.inputs[0].sighash_type.unwrap().to_u32(), v);
        let a = s.analyze(&psbt);
        let r = s.sign(&mut psbt);
        if v <= 1 {
            assert_eq!(r.unwrap(), 1, "{v:#x}");
            assert!(a.is_ok());
            let sig = psbt.inputs[0].tap_key_sig.unwrap();
            assert_eq!(sig.sighash_type as u8 as u32, v);
            check_signatures(&psbt, Network::Bitcoin);
        } else {
            assert!(r.is_err() && a.is_err(), "{v:#x} must be refused");
            assert!(psbt.inputs[0].tap_key_sig.is_none());
        }
        let mut foreign = spend_to_foreign(&[single_spk(), foreign_spk(3)]);
        foreign.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(v));
        assert_eq!(
            s.sign(&mut foreign).unwrap(),
            1,
            "foreign {v:#x} is not ours to judge"
        );
        check_signatures(&foreign, Network::Bitcoin);
    }
}

#[test]
fn change_labels() {
    let cases: Vec<(Network, &str, bool)> = vec![
        (Network::Testnet, "86'/1'/0'/1/0", true),
        (Network::Testnet, "86'/1'/0'/1/999", true),
        (Network::Testnet, "86'/1'/0'/1/1000", false),
        (Network::Testnet, "86'/1'/0'/1/2147483647", false),
        (Network::Testnet, "86'/1'/0'/1/999'", false),
        (Network::Testnet, "86'/1'/1'/1/0", false),
        (Network::Testnet, "86'/1'/5'/1/0", false),
        (Network::Testnet, "86'/1'/2147483647'/1/0", false),
        (Network::Testnet, "86'/1'/0'/0/0", false),
        (Network::Testnet, "86'/0'/0'/1/0", false),
        (Network::Testnet, "86'/1'/0/1/0", false),
        (Network::Bitcoin, "86'/0'/0'/1/0", true),
        (Network::Bitcoin, "86'/0'/0'/1/999", true),
        (Network::Bitcoin, "86'/0'/0'/1/1000", false),
        (Network::Bitcoin, "86'/1'/0'/1/0", false),
        (Network::Signet, "86'/1'/0'/1/0", true),
        (Network::Regtest, "86'/1'/0'/1/0", true),
    ];
    for (net, p, want) in cases {
        let s = signer(net);
        let p = path(p);
        let k = child_key(&p);
        let mut psbt = psbt_with(&[(single_spk(), 50_000)], &[(bip86_spk(k), 1_000)]);
        origin_out(&mut psbt, 0, k, fp(), p.clone());
        assert_eq!(
            s.analyze(&psbt).unwrap().outputs[0].is_change,
            want,
            "{net:?} {p}"
        );
        check_change(&psbt, net, &s);
        let mut wrong_fp = psbt.clone();
        wrong_fp.outputs[0].tap_key_origins.clear();
        origin_out(&mut wrong_fp, 0, k, Fingerprint::from([0; 4]), p.clone());
        assert!(!s.analyze(&wrong_fp).unwrap().outputs[0].is_change);
    }
    let s = signer(Network::Testnet);
    let weird = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 86 },
        ChildNumber::Hardened { index: 1 },
        ChildNumber::Hardened { index: 0 },
        ChildNumber::Normal { index: 1 },
        ChildNumber::Normal { index: u32::MAX },
    ]);
    let weird_key = master()
        .derive_priv(secp(), &weird)
        .map(|x| x.to_keypair(secp()).x_only_public_key().0);
    eprintln!(
        "[info] derive_priv at Normal{{u32::MAX}}: {:?}",
        weird_key.as_ref().map(|_| "ok")
    );
    if let Ok(k) = weird_key {
        let mut psbt = psbt_with(&[(bip86_spk(k), 50_000)], &[(bip86_spk(k), 1_000)]);
        origin_out(&mut psbt, 0, k, fp(), weird.clone());
        origin_in(&mut psbt, 0, k, fp(), weird.clone());
        assert!(!s.analyze(&psbt).unwrap().outputs[0].is_change);
        let n = s.sign(&mut psbt).unwrap();
        eprintln!("[info] input at programmatic Normal{{u32::MAX}} path signed={n}");
        let rt = Psbt::deserialize(&psbt.serialize()).unwrap();
        eprintln!(
            "[info] after wire roundtrip the path reads {}",
            rt.inputs[0].tap_key_origins.values().next().unwrap().1 .1
        );
    }
}

#[test]
fn cross_network_paths() {
    let main = signer(Network::Bitcoin);
    let test = signer(Network::Testnet);
    for (s, net, p) in [
        (&main, Network::Bitcoin, "86'/1'/0'/0/0"),
        (&test, Network::Testnet, "86'/0'/0'/0/0"),
    ] {
        let p = path(p);
        let k = child_key(&p);
        let mut psbt = spend_to_foreign(&[bip86_spk(k)]);
        origin_in(&mut psbt, 0, k, fp(), p.clone());
        assert_eq!(s.sign(&mut psbt).unwrap(), 0, "{net:?} {p}");
    }
    for net in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ] {
        // The single-key output is the same on every network, so only a mainnet
        // signer spends it.
        let mut psbt = spend_to_foreign(&[single_spk()]);
        assert_eq!(
            signer(net).sign(&mut psbt).unwrap(),
            usize::from(net == Network::Bitcoin),
            "single key on {net:?}"
        );
    }
}

#[test]
fn duplicate_outpoints() {
    let s = signer(Network::Bitcoin);
    let mut psbt = spend_to_foreign(&[single_spk(), single_spk()]);
    psbt.unsigned_tx.input[1].previous_output = psbt.unsigned_tx.input[0].previous_output;
    let a = s.analyze(&psbt).unwrap();
    let n = s.sign(&mut psbt).unwrap();
    eprintln!(
        "[info] duplicate outpoint: total_input_sats={} (one utxo of 50000) signable={:?} signed={n}",
        a.total_input_sats, a.signable_inputs
    );
    check_signatures(&psbt, Network::Bitcoin);
}

#[test]
fn mismatched_map_lengths_do_not_panic() {
    let s = signer(Network::Bitcoin);
    let mut extra_in = spend_to_foreign(&[single_spk()]);
    extra_in.inputs.push(Input {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: single_spk(),
        }),
        ..Default::default()
    });
    let _ = s.analyze(&extra_in);
    assert!(s.sign(&mut extra_in).is_err());
    assert!(extra_in.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    let mut fewer_in = spend_to_foreign(&[single_spk(), single_spk()]);
    fewer_in.inputs.pop();
    let _ = s.analyze(&fewer_in);
    assert!(s.sign(&mut fewer_in).is_err());
    assert!(fewer_in.inputs.iter().all(|i| i.tap_key_sig.is_none()));
    let mut fewer_out = spend_to_foreign(&[single_spk()]);
    fewer_out.outputs.clear();
    assert!(!s.analyze(&fewer_out).unwrap().outputs[0].is_change);
}

fn wallet_inputs_psbt(n: usize, with_origins: bool) -> Psbt {
    let acct = master().derive_priv(secp(), &path("86'/1'/0'/0")).unwrap();
    let spks_keys: Vec<(ScriptBuf, Option<(XOnlyPublicKey, u32)>)> = (0..n as u32)
        .map(|i| {
            if with_origins {
                let k = acct
                    .derive_priv(secp(), &[ChildNumber::Normal { index: i }])
                    .unwrap()
                    .to_keypair(secp())
                    .x_only_public_key()
                    .0;
                (bip86_spk(k), Some((k, i)))
            } else {
                (single_spk(), None)
            }
        })
        .collect();
    let ins: Vec<_> = spks_keys.iter().map(|(s, _)| (s.clone(), 10_000)).collect();
    let mut psbt = psbt_with(&ins, &[(foreign_spk(2), 1_000)]);
    for (i, (_, ko)) in spks_keys.iter().enumerate() {
        if let Some((k, idx)) = ko {
            origin_in(&mut psbt, i, *k, fp(), path(&format!("86'/1'/0'/0/{idx}")));
        }
    }
    psbt
}

#[test]
#[ignore]
fn timing_many_inputs() {
    let counts: Vec<usize> = std::env::var("STRESS_INPUTS")
        .map(|v| v.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|_| vec![500, 1000, 2000, 4000, 8000]);
    for n in counts {
        for with_origins in [false, true] {
            let net = if with_origins {
                Network::Testnet
            } else {
                Network::Bitcoin
            };
            let s = signer(net);
            let psbt = wallet_inputs_psbt(n, with_origins);
            let bytes = psbt.serialize();
            let mut psbt = timed(
                &format!("parse n={n} origins={with_origins} ({} bytes)", bytes.len()),
                || Psbt::deserialize(&bytes).unwrap(),
            );
            let a = timed(&format!("analyze n={n} origins={with_origins}"), || {
                s.analyze(&psbt).unwrap()
            });
            assert_eq!(a.signable_inputs.len(), n);
            let signed = timed(&format!("sign n={n} origins={with_origins}"), || {
                s.sign(&mut psbt).unwrap()
            });
            assert_eq!(signed, n);
            if n <= 2000 {
                assert_eq!(check_signatures(&psbt, net).len(), n);
            }
        }
    }
}

#[test]
#[ignore]
fn timing_many_outputs_and_origins() {
    let s = signer(Network::Testnet);
    let n_out: usize = std::env::var("STRESS_OUTPUTS")
        .map(|v| v.parse().unwrap())
        .unwrap_or(80_000);
    let ck = child_key(&path("86'/1'/0'/1/0"));
    let outs: Vec<_> = (0..n_out).map(|_| (bip86_spk(ck), 1u64)).collect();
    let mut psbt = psbt_with(&[(single_spk(), u64::MAX / 2)], &outs);
    for i in 0..n_out {
        origin_out(&mut psbt, i, ck, fp(), path("86'/1'/0'/1/0"));
    }
    let bytes = psbt.serialize();
    let psbt = timed(
        &format!("parse {n_out} change outputs ({} bytes)", bytes.len()),
        || Psbt::deserialize(&bytes).unwrap(),
    );
    let a = timed(&format!("analyze {n_out} change outputs"), || {
        s.analyze(&psbt).unwrap()
    });
    assert!(a.outputs.iter().all(|o| o.is_change));

    let n_orig: u32 = std::env::var("STRESS_ORIGINS")
        .map(|v| v.parse().unwrap())
        .unwrap_or(50_000);
    let p0 = path("86'/1'/0'/0/0");
    let k0 = child_key(&p0);
    let mut psbt = spend_to_foreign(&[bip86_spk(k0)]);
    for n in 1..=n_orig {
        let mut sk = [0u8; 32];
        sk[28..].copy_from_slice(&n.to_be_bytes());
        let k = Keypair::from_seckey_slice(secp(), &sk)
            .unwrap()
            .x_only_public_key()
            .0;
        origin_in(&mut psbt, 0, k, fp(), path(&format!("86'/1'/0'/0/{n}")));
    }
    origin_in(&mut psbt, 0, k0, fp(), p0);
    let bytes = psbt.serialize();
    let mut psbt = timed(
        &format!("parse {n_orig} forged origins ({} bytes)", bytes.len()),
        || Psbt::deserialize(&bytes).unwrap(),
    );
    timed(&format!("analyze {n_orig} forged origins"), || {
        s.analyze(&psbt).unwrap()
    });
    let n = timed(&format!("sign {n_orig} forged origins"), || {
        s.sign(&mut psbt).unwrap()
    });
    assert_eq!(n, 1);
    check_signatures(&psbt, Network::Testnet);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    fn pick<T: Clone>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize].clone()
    }
}

fn random_path(r: &mut Rng) -> DerivationPath {
    let h = |index| ChildNumber::Hardened { index };
    let n = |index| ChildNumber::Normal { index };
    let rnd = r.below(2000) as u32;
    let mut c = vec![
        r.pick(&[h(86), h(86), h(86), h(84), n(86)]),
        r.pick(&[h(0), h(1), h(1), n(1), h(2)]),
        r.pick(&[h(0), h(0), h(1), h(5), h(0x7fff_ffff), n(0)]),
        r.pick(&[n(0), n(1), n(1), n(2), h(1)]),
        r.pick(&[n(0), n(1), n(999), n(1000), n(0x7fff_ffff), h(5), n(rnd)]),
    ];
    match r.below(10) {
        0 => {
            c.truncate(r.below(5) as usize);
        }
        1 => c.extend((0..r.below(4)).map(|i| n(i as u32))),
        _ => {}
    }
    DerivationPath::from(c)
}

fn random_amount(r: &mut Rng) -> u64 {
    let rnd = r.below(1 << 40);
    r.pick(&[
        0,
        1,
        546,
        10_000,
        50_000,
        2_100_000_000_000_000,
        u64::MAX / 2,
        u64::MAX,
        rnd,
    ])
}

fn mangle(r: &mut Rng, spk: &ScriptBuf) -> ScriptBuf {
    let mut b = spk.to_bytes();
    match r.below(5) {
        0 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b[i] ^= 1 << r.below(8);
        }
        1 => b.truncate(r.below(b.len() as u64 + 1) as usize),
        2 => b.push(r.next() as u8),
        3 if b.len() == 34 => b[2..34].copy_from_slice(&[0xff; 32]),
        _ => {
            if b.len() == 34 {
                b[0] = r.pick(&[0x00, 0x52, 0x60, 0x51]);
            }
        }
    }
    ScriptBuf::from_bytes(b)
}

/// (spk, Some(key, path)) for the origin to attach, if any.
fn random_spk(r: &mut Rng) -> (ScriptBuf, Option<(XOnlyPublicKey, DerivationPath)>) {
    match r.below(6) {
        0 => (single_spk(), None),
        1 | 2 => {
            let p = random_path(r);
            match master().derive_priv(secp(), &p) {
                Ok(x) => {
                    let k = x.to_keypair(secp()).x_only_public_key().0;
                    (bip86_spk(k), Some((k, p)))
                }
                Err(_) => (single_spk(), None),
            }
        }
        3 => (foreign_spk(1 + r.below(200) as u8), None),
        4 => {
            let (s, o) = random_spk(r);
            (mangle(r, &s), o)
        }
        _ => (
            ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                single_key(),
            )),
            None,
        ),
    }
}

fn random_psbt(r: &mut Rng) -> Psbt {
    let n_in = 1 + r.below(4) as usize;
    let n_out = r.below(4) as usize;
    let ins: Vec<_> = (0..n_in)
        .map(|_| (random_spk(r), random_amount(r)))
        .collect();
    let outs: Vec<_> = (0..n_out)
        .map(|_| {
            if r.chance(40) {
                let i = r.pick(&[0u32, 1, 999, 1000]);
                let p = path(&format!(
                    "86'/{}'/{}'/1/{i}",
                    r.below(2),
                    r.pick(&[0, 0, 1])
                ));
                let k = child_key(&p);
                ((bip86_spk(k), Some((k, p))), random_amount(r))
            } else {
                (random_spk(r), random_amount(r))
            }
        })
        .collect();
    let mut psbt = psbt_with(
        &ins.iter()
            .map(|((s, _), v)| (s.clone(), *v))
            .collect::<Vec<_>>(),
        &outs
            .iter()
            .map(|((s, _), v)| (s.clone(), *v))
            .collect::<Vec<_>>(),
    );
    let sighashes = [0u32, 1, 1, 2, 3, 0x81, 0x83, 4, 0x100, 0x101, u32::MAX];
    for (i, ((_, o), _)) in ins.iter().enumerate() {
        if let Some((k, p)) = o {
            if r.chance(90) {
                let f = if r.chance(90) {
                    fp()
                } else {
                    Fingerprint::from([r.next() as u8; 4])
                };
                let key = if r.chance(90) {
                    *k
                } else {
                    child_key(&random_path(r))
                };
                let leaves = if r.chance(95) {
                    vec![]
                } else {
                    vec![TapLeafHash::all_zeros()]
                };
                psbt.inputs[i]
                    .tap_key_origins
                    .insert(key, (leaves, (f, p.clone())));
            }
        }
        for _ in 0..r.below(3) {
            psbt.inputs[i].tap_key_origins.insert(
                key_of(1 + r.below(250) as u8),
                (vec![], (fp(), random_path(r))),
            );
        }
        if r.chance(20) {
            psbt.inputs[i].sighash_type = Some(PsbtSighashType::from_u32(r.pick(&sighashes)));
        }
        if r.chance(8) {
            psbt.inputs[i].tap_merkle_root =
                Some(TapNodeHash::from_byte_array([r.next() as u8; 32]));
        }
        if r.chance(10) {
            psbt.inputs[i].tap_internal_key = Some(key_of(1 + r.below(250) as u8));
        }
        if r.chance(3) {
            psbt.inputs[i].witness_utxo = None;
        }
    }
    for (i, ((_, o), _)) in outs.iter().enumerate() {
        if let Some((k, p)) = o {
            if r.chance(85) {
                let key = if r.chance(90) {
                    *k
                } else {
                    child_key(&random_path(r))
                };
                let f = if r.chance(95) {
                    fp()
                } else {
                    Fingerprint::from([1, 2, 3, 4])
                };
                psbt.outputs[i]
                    .tap_key_origins
                    .insert(key, (vec![], (f, p.clone())));
            }
        }
    }
    if n_in > 1 && r.chance(5) {
        psbt.unsigned_tx.input[1].previous_output = psbt.unsigned_tx.input[0].previous_output;
    }
    psbt
}

fn run_case(psbt: &Psbt, net: Network, s: &PsbtSigner, b: &BitcoinSigner) -> usize {
    let mut pre = psbt.clone();
    for i in pre.inputs.iter_mut() {
        i.tap_key_sig = None;
    }
    let analysis = s.analyze(&pre);
    check_change(&pre, net, s);
    let mut signed_psbt = pre.clone();
    let r = s.sign(&mut signed_psbt);
    match &r {
        Ok(n) => {
            let idx = check_signatures(&signed_psbt, net);
            assert_eq!(idx.len(), *n);
            if let Ok(a) = &analysis {
                assert_eq!(a.signable_inputs, idx, "analyze and sign disagree");
            }
        }
        Err(_) => assert!(signed_psbt.inputs.iter().all(|i| i.tap_key_sig.is_none())),
    }
    let mut via_policy = pre.clone();
    match b.sign_psbt(&mut via_policy) {
        Ok(_) => {
            assert!(analysis.is_ok());
            check_signatures(&via_policy, net);
        }
        Err(_) => assert!(via_policy.inputs.iter().all(|i| i.tap_key_sig.is_none())),
    }
    r.unwrap_or(0)
}

#[test]
fn fuzz_random_psbt_mutations() {
    let iters: u64 = std::env::var("STRESS_FUZZ_ITERS")
        .map(|v| v.parse().unwrap())
        .unwrap_or(1000);
    let seed: u64 = std::env::var("STRESS_FUZZ_SEED")
        .map(|v| v.parse().unwrap())
        .unwrap_or(0x5eed_1234_abcd_0001);
    let nets = [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ];
    let signers: Vec<_> = nets.iter().map(|n| (signer(*n), btc_signer(*n))).collect();
    let mut r = Rng(seed);
    let (mut total_signed, mut wire_ok, mut flipped_ok) = (0usize, 0usize, 0usize);
    for it in 0..iters {
        let ni = r.below(4) as usize;
        let net = nets[ni];
        let (s, b) = &signers[ni];
        let psbt = random_psbt(&mut r);
        let bytes = psbt.serialize();
        let mut flipped = bytes.clone();
        for _ in 0..1 + r.below(3) {
            let i = r.below(flipped.len() as u64) as usize;
            flipped[i] ^= 1 << r.below(8);
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut n = 0;
            let mut wire = 0;
            let mut flip = 0;
            if let Ok(p) = Psbt::deserialize(&bytes) {
                wire += 1;
                n += run_case(&p, net, s, b);
            } else {
                n += run_case(&psbt, net, s, b);
            }
            if let Ok(p) = Psbt::deserialize(&flipped) {
                flip += 1;
                n += run_case(&p, net, s, b);
            }
            (n, wire, flip)
        }));
        match outcome {
            Ok((n, w, f)) => {
                total_signed += n;
                wire_ok += w;
                flipped_ok += f;
            }
            Err(e) => {
                use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
                eprintln!(
                    "FAIL seed={seed:#x} iter={it} net={net:?}\npsbt={}\nflipped={}",
                    STANDARD.encode(&bytes),
                    STANDARD.encode(&flipped)
                );
                std::panic::resume_unwind(e);
            }
        }
    }
    eprintln!(
        "[fuzz] iters={iters} seed={seed:#x} signatures_checked={total_signed} wire_roundtrips={wire_ok} flipped_parsed={flipped_ok}"
    );
    assert!(total_signed > 0);
}
