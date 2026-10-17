// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep wallet sign` over relays: a requester and a co-signer, each a real
//! `keep` process with one share, sign a key-path spend of the group's own
//! addresses against an in-process relay. Needs the `local-relay-tests`
//! feature, which lets the binary use a loopback ws:// relay.
#![cfg(feature = "local-relay-tests")]

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use common::{frost_wallet_psbt, npub_in, read_psbt, signed_key_path_inputs, write_psbt};
use tempfile::TempDir;

const PASSWORD: &str = "testpass123";

fn keep(vault: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keep"));
    cmd.arg("--path")
        .arg(vault)
        .env("KEEP_PASSWORD", PASSWORD)
        .stdin(Stdio::null());
    cmd
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().expect("run keep");
    assert!(
        out.status.success(),
        "{:?}\nstdout: {}\nstderr: {}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// A co-signer serving share 2. `policy` is the key-path spend policy it
/// serves with, as the operator types it: the destinations every output must
/// pay and the most the spend may consume. `None` serves the default, which
/// refuses every spend.
struct CoSigner(Child);

impl CoSigner {
    fn start(vault: &Path, npub: &str, relay: &str, policy: Option<(&[String], u64, u64)>) -> Self {
        let mut cmd = keep(vault);
        cmd.args([
            "frost",
            "network",
            "serve",
            "--group",
            npub,
            "--relay",
            relay,
            "--insecure-no-attestation",
        ])
        // Captured, not nulled: a serve that dies on its arguments would
        // otherwise show up only as the 60s sign timeout further down.
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        if let Some((destinations, max_sats, max_fee_sats)) = policy {
            for destination in destinations {
                cmd.args(["--key-spend-to", destination]);
            }
            cmd.args(["--key-spend-max-sats", &max_sats.to_string()]);
            cmd.args(["--key-spend-max-fee-sats", &max_fee_sats.to_string()]);
        }
        let mut child = cmd.spawn().expect("spawn serve");
        // A clap error exits immediately; a serving node does not exit at all.
        std::thread::sleep(std::time::Duration::from_millis(500));
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("serve exited with {status}: {stderr}");
        }
        // Drained for the rest of the test: the pipe holds about 64 KiB, and a
        // serve that filled it would block instead of co-signing.
        if let Some(mut pipe) = child.stderr.take() {
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut pipe, &mut std::io::sink());
            });
        }
        Self(child)
    }
}

impl Drop for CoSigner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_sign_spends_with_a_co_signer_that_opts_in() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let relay = common::start_mock_relay().await;
    let relay_url = relay.url().await.to_string();
    let dir = TempDir::new().unwrap();
    let (requester, cosigner) = (dir.path().join("requester"), dir.path().join("cosigner"));

    run(keep(&requester).arg("init"));
    let generated = run(keep(&requester).args([
        "frost",
        "generate",
        "--threshold",
        "2",
        "--shares",
        "3",
        "--name",
        "g",
    ]));
    let npub = npub_in(&generated);
    let group = keep_core::keys::npub_to_bytes(&npub).unwrap();
    run(keep(&requester).args([
        "wallet",
        "descriptor",
        "--group",
        &npub,
        "--network",
        "regtest",
    ]));

    let export = run(keep(&requester).args(["frost", "export", "--share", "2", "--group", &npub]));
    let export = String::from_utf8(export.stdout).unwrap();
    run(keep(&cosigner).arg("init"));
    let mut import = keep(&cosigner)
        .args(["frost", "import"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(import.stdin.take().unwrap(), "{}\n", export.trim()).unwrap();
    assert!(import.wait_with_output().unwrap().status.success());

    let psbt_file = dir.path().join("spend.psbt");
    let spend = frost_wallet_psbt(&group, 1, &[[0, 2], [1, 4]]);
    // What the operator would put behind `--key-spend-to`: every output of this
    // spend, the group's change included, as the co-signer compares scripts and
    // refuses any output it was not given. The cap is what the spend consumes,
    // its outputs plus the fee, which is the three 100 000 sat inputs.
    let destinations: Vec<String> = spend
        .unsigned_tx
        .output
        .iter()
        .map(|o| {
            bitcoin::Address::from_script(&o.script_pubkey, bitcoin::Network::Regtest)
                .expect("each output must render as an address")
                .to_string()
        })
        .collect();
    let consumed = spend
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum::<u64>();
    let paid = spend
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum::<u64>();
    // This fixture is not fee-realistic: three 100 000 sat inputs pay out
    // 99 000, so the operator has to allow the 201 000 sat remainder for it to
    // be co-signed at all.
    let fee = consumed - paid;
    write_psbt(&psbt_file, &spend);
    let sign = |output: &Path| {
        let mut cmd = keep(&requester);
        cmd.args([
            "wallet",
            "sign",
            "--group",
            &npub,
            "--psbt",
            psbt_file.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--relay",
            &relay_url,
            "--share",
            "1",
            "--timeout",
            "60",
            "--any-network",
            "--yes",
        ]);
        cmd.output().expect("run wallet sign")
    };

    {
        let _co_signer = CoSigner::start(
            &cosigner,
            &npub,
            &relay_url,
            Some((&destinations, consumed, fee)),
        );
        let signed = dir.path().join("signed.psbt");
        let out = sign(&signed);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(signed_key_path_inputs(&read_psbt(&signed)), vec![0, 1]);
    }

    let _co_signer = CoSigner::start(&cosigner, &npub, &relay_url, None);
    let refused = dir.path().join("refused.psbt");
    let out = sign(&refused);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a co-signer that has not opted in must refuse"
    );
    assert!(
        stderr.contains("does not approve key-path spends"),
        "{stderr}"
    );
    assert!(!refused.exists());
}
