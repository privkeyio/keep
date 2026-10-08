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

/// A co-signer serving share 2, opting in to key-path spends or not.
struct CoSigner(Child);

impl CoSigner {
    fn start(vault: &Path, npub: &str, relay: &str, allow: bool) -> Self {
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
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        if allow {
            cmd.arg("--allow-key-path-spend");
        }
        Self(cmd.spawn().expect("spawn serve"))
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
    let relay = nostr_relay_builder::MockRelay::run().await.expect("relay");
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
    write_psbt(&psbt_file, &frost_wallet_psbt(&group, 1, &[[0, 2], [1, 4]]));
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
        let _co_signer = CoSigner::start(&cosigner, &npub, &relay_url, true);
        let signed = dir.path().join("signed.psbt");
        let out = sign(&signed);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(signed_key_path_inputs(&read_psbt(&signed)), vec![0, 1]);
    }

    let _co_signer = CoSigner::start(&cosigner, &npub, &relay_url, false);
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
