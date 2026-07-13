use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "testpass123";
const TEST_HIDDEN_PASSWORD: &str = "hiddenpass456";

fn keep_binary() -> Option<PathBuf> {
    let mut path = std::env::current_exe().ok()?;
    path.pop();
    path.pop();
    path.push("keep");
    if path.exists() {
        return Some(path);
    }
    path.pop();
    path.push("debug");
    path.push("keep");
    if path.exists() {
        return Some(path);
    }
    path.pop();
    path.pop();
    path.push("release");
    path.push("keep");
    if path.exists() {
        return Some(path);
    }
    None
}

macro_rules! require_binary {
    () => {
        match keep_binary() {
            Some(p) => p,
            None => {
                eprintln!("SKIPPED: keep binary not found (build with: cargo build -p keep-cli --features testing)");
                return;
            }
        }
    };
}

struct KeepCmd {
    cmd: Command,
}

impl KeepCmd {
    fn new(binary: &Path) -> Self {
        let mut cmd = Command::new(binary);
        cmd.env("KEEP_PASSWORD", TEST_PASSWORD);
        cmd.env("KEEP_YES", "1");
        Self { cmd }
    }

    fn path(mut self, path: &Path) -> Self {
        self.cmd.arg("--path").arg(path);
        self
    }

    fn hidden(mut self) -> Self {
        self.cmd.arg("--hidden");
        self.cmd.env("KEEP_HIDDEN_PASSWORD", TEST_HIDDEN_PASSWORD);
        self
    }

    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.cmd.args(args);
        self
    }

    fn env(mut self, key: &str, val: &str) -> Self {
        self.cmd.env(key, val);
        self
    }

    fn run(mut self) -> Output {
        // Pin stdin to /dev/null so it is deterministically NOT a TTY rather
        // than inheriting the parent's (a TTY under interactive `cargo test`).
        // The export gate also refuses on its automation-env branch because
        // `KeepCmd::new` always sets KEEP_YES, but pinning stdin keeps the gate
        // independent of the ambient terminal regardless.
        self.cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = self.cmd.spawn().expect("failed to spawn");
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return child.wait_with_output().expect("failed to wait"),
                Ok(None) if start.elapsed() > Duration::from_secs(60) => {
                    child.kill().ok();
                    panic!("command timed out after 60 seconds");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("error waiting for child: {e}"),
            }
        }
    }
}

fn assert_success(output: &Output) {
    if output.status.success() {
        return;
    }
    eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
    panic!("command failed with status: {:?}", output.status);
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected command to fail but it succeeded"
    );
}

fn output_contains(output: &Output, needle: &str) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout.contains(needle) || stderr.contains(needle)
}

fn assert_interactive_refusal(output: &Output) {
    assert_failure(output);
    assert!(output_contains(output, "interactive-only"));
    assert!(output_contains(output, "#467"));
}

#[test]
fn test_init_generate_list_export_workflow() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("test-vault");

    let output = KeepCmd::new(&bin).path(&vault).args(["init"]).run();
    assert_success(&output);
    assert!(output_contains(&output, "Keep created"));

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args(["generate", "--name", "testkey"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "Generated new key"));
    assert!(output_contains(&output, "testkey"));

    let output = KeepCmd::new(&bin).path(&vault).args(["list"]).run();
    assert_success(&output);
    assert!(output_contains(&output, "testkey"));
    assert!(output_contains(&output, "Nostr"));

    // `export` is interactive-only by design (#467): no TTY in this test
    // harness means the command must refuse rather than print an nsec.
    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args(["export", "--name", "testkey"])
        .run();
    assert_interactive_refusal(&output);
}

/// The #467 gate must fire BEFORE the vault is opened. Pointed at a vault that
/// was never created, the command must refuse with the interactive-only policy
/// error rather than a not-found error, proving the gate short-circuits ahead
/// of `Keep::open`. Both the regular and `--hidden` dispatch arms share the
/// single gate at the top of `cmd_export`, so both are pinned here.
#[test]
fn test_export_refuses_before_touching_vault() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("never-created-vault");

    let output = KeepCmd::new(&bin)
        .path(&nonexistent)
        .args(["export", "--name", "irrelevant"])
        .run();
    assert_interactive_refusal(&output);

    let output = KeepCmd::new(&bin)
        .hidden()
        .path(&nonexistent)
        .args(["export", "--name", "irrelevant"])
        .run();
    assert_interactive_refusal(&output);
}

#[test]
fn test_multiple_keys() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("multi-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    for name in ["key1", "key2", "key3"] {
        let output = KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", name])
            .run();
        assert_success(&output);
    }

    let output = KeepCmd::new(&bin).path(&vault).args(["list"]).run();
    assert_success(&output);
    assert!(output_contains(&output, "key1"));
    assert!(output_contains(&output, "key2"));
    assert!(output_contains(&output, "key3"));
    assert!(output_contains(&output, "3 key(s)"));
}

#[test]
fn test_delete_key() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("delete-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "todelete"])
            .run(),
    );

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args(["delete", "--name", "todelete"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "Deleted key"));

    let output = KeepCmd::new(&bin).path(&vault).args(["list"]).run();
    assert_success(&output);
    assert!(!output_contains(&output, "todelete"));
    assert!(output_contains(&output, "No keys found"));
}

/// `export` is interactive-only by design (#467), so the original
/// generate -> export -> import -> list roundtrip via the CLI is no longer
/// possible non-interactively. This test now covers the import half against
/// a fixed test nsec (the export half is asserted to REFUSE in
/// `test_init_generate_list_export_workflow`).
#[test]
fn test_import_nsec_into_fresh_vault() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("import-vault");

    // Deterministic test nsec - never used for anything real. Generated once
    // and pinned so the test is hermetic.
    const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .env("KEEP_NSEC", TEST_NSEC)
        .args(["import", "--name", "imported"])
        .run();
    assert_success(&output);

    let output = KeepCmd::new(&bin).path(&vault).args(["list"]).run();
    assert_success(&output);
    assert!(output_contains(&output, "imported"));
}

#[test]
fn test_frost_generate_list_sign() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("frost-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "generate",
            "--threshold",
            "2",
            "--shares",
            "3",
            "--name",
            "testgroup",
        ])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "Generated FROST key group"));
    assert!(output_contains(&output, "2-of-3"));

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args(["frost", "list"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "testgroup"));
    assert!(output_contains(&output, "3 share(s)"));

    let msg_hex = hex::encode(sha2::Sha256::digest(b"test message"));
    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            &msg_hex,
            "--group",
            "testgroup",
        ])
        .run();
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|l| l.len() == 128 && l.chars().all(|c| c.is_ascii_hexdigit())),
        "expected 64-byte hex signature in output"
    );
}

#[test]
fn test_hidden_volume_workflow() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("hidden-vault");

    let output = KeepCmd::new(&bin)
        .hidden()
        .path(&vault)
        .args(["init", "--size", "1"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "Keep created"));

    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "outerkey"])
            .run(),
    );

    let output = KeepCmd::new(&bin)
        .hidden()
        .path(&vault)
        .args(["generate", "--name", "hiddenkey"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "hidden volume"));

    let output = KeepCmd::new(&bin).path(&vault).args(["list"]).run();
    assert_success(&output);
    assert!(output_contains(&output, "outerkey"));
    assert!(!output_contains(&output, "hiddenkey"));

    let output = KeepCmd::new(&bin)
        .hidden()
        .path(&vault)
        .args(["list"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "hiddenkey"));
    assert!(!output_contains(&output, "outerkey"));
}

#[test]
fn test_wrong_password_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("wrongpw-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "mykey"])
            .run(),
    );

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .env("KEEP_PASSWORD", "wrongpassword")
        .args(["list"])
        .run();
    assert_failure(&output);
}

#[test]
fn test_missing_vault_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("does-not-exist");

    assert_failure(&KeepCmd::new(&bin).path(&nonexistent).args(["list"]).run());
}

// Note: there is no `test_export_nonexistent_key_fails` here. `export` is now
// interactive-only (#467) and this harness is always non-interactive
// (KEEP_YES set, stdin pinned to null), so the gate refuses before the key
// lookup is ever reached. The nonexistent-key path is unreachable via the CLI
// non-interactively; the gate behavior itself is covered by
// `test_export_refuses_before_touching_vault`.

#[test]
fn test_delete_nonexistent_key_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("nodelete-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_failure(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["delete", "--name", "nonexistent"])
            .run(),
    );
}

#[test]
fn test_short_password_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("shortpw-vault");

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .env("KEEP_PASSWORD", "short")
        .args(["init"])
        .run();
    assert_failure(&output);
    assert!(output_contains(&output, "8 characters"));
}

#[test]
fn test_version_flag() {
    let bin = require_binary!();
    let output = Command::new(&bin)
        .arg("--version")
        .output()
        .expect("failed to run");
    assert_success(&output);
    assert!(output_contains(&output, "keep"));
}

#[test]
fn test_help_flag() {
    let bin = require_binary!();
    let output = Command::new(&bin)
        .arg("--help")
        .output()
        .expect("failed to run");
    assert_success(&output);
    assert!(output_contains(&output, "Sovereign key management"));
}

// === #440: `frost sign` non-interactive coverage ===
//
// The existing `test_frost_generate_list_sign` only checks the signature is
// 64 hex bytes. These tests:
//
// 1. Pin that the produced signature actually VERIFIES against the group
//    pubkey under BIP-340. The existing test would still pass if a regression
//    emitted any garbage 64-byte hex value; this one wouldn't.
// 2. Pin that a malformed message hex is refused with a clean error rather
//    than panicking or silently signing nonsense bytes.
// 3. Pin that an unknown group identifier surfaces a clean "not found"
//    rather than an obscure failure downstream.

/// Extract a 64-byte hex signature line from `frost sign` stdout.
fn extract_signature_hex(output: &Output) -> [u8; 64] {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sig_hex = stdout
        .lines()
        .find(|l| l.len() == 128 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| {
            panic!(
                "no 128-char hex line in stdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let bytes = hex::decode(sig_hex).expect("decode signature hex");
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    sig
}

#[test]
fn test_frost_sign_signature_verifies_against_group_pubkey() {
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    use keep_core::Keep;

    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("verify-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    let gen_output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "generate",
            "--threshold",
            "2",
            "--shares",
            "3",
            "--name",
            "verifygroup",
        ])
        .run();
    assert_success(&gen_output);

    // Read the actual group pubkey out of the vault. The CLI `frost list`
    // truncates the npub for display, so we can't parse it back; in-process
    // access via `keep_core::Keep` is exact.
    let group_pubkey: [u8; 32] = {
        let mut keep = Keep::open(&vault).unwrap();
        keep.unlock(TEST_PASSWORD).unwrap();
        let shares = keep.frost_list_shares().unwrap();
        let share = shares
            .iter()
            .find(|s| s.metadata.name == "verifygroup")
            .expect("verifygroup share must exist after generate");
        share.metadata.group_pubkey
    };

    let message_digest: [u8; 32] = sha2::Sha256::digest(b"verifiable signing payload").into();
    let msg_hex = hex::encode(message_digest);

    let sign_output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            &msg_hex,
            "--group",
            "verifygroup",
        ])
        .run();
    assert_success(&sign_output);

    let sig_bytes = extract_signature_hex(&sign_output);
    let signature = schnorr::Signature::from_slice(&sig_bytes).expect("valid schnorr signature");
    let msg = Message::from_digest(message_digest);
    let xonly =
        XOnlyPublicKey::from_slice(&group_pubkey).expect("group pubkey is a valid x-only point");
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &msg, &xonly).expect(
        "`frost sign` output MUST verify against the group pubkey \
         via BIP-340 schnorr",
    );
}

#[test]
fn test_frost_sign_rejects_malformed_message_hex() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("bad-hex-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    // `--message` hex is decoded before the vault is opened or any group is
    // resolved, so no frost share setup is needed: odd-length / non-hex input
    // must be refused cleanly regardless of group state.
    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            "ZZZ-not-hex",
            "--group",
            "badhex",
        ])
        .run();
    assert_failure(&output);
    assert!(
        output_contains(&output, "invalid message hex"),
        "malformed hex must surface a clean error, got:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_frost_sign_rejects_unknown_group() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("no-group-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    // No frost share generated; the lookup must fail cleanly rather than
    // panic or sign with a random share.
    let msg_hex = hex::encode(sha2::Sha256::digest(b"x"));
    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            &msg_hex,
            "--group",
            "nosuchgroup",
        ])
        .run();
    assert_failure(&output);
    assert!(
        output_contains(&output, "No group found"),
        "unknown group must surface a clean 'not found' error, got:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// === #433: WDC CLI pre-vault validation coverage ===
//
// `wallet propose` validates `--timeout` and `--network` BEFORE opening the
// vault, so these tests don't need a real frost share to pin the gates.
// They use a temp path that does NOT have a vault, plus any-string args for
// the other required parameters: the validation fires before any of those
// are dereferenced.
//
// Each input is one of the boundary cases documented in #418's smoke notes;
// pinning them here makes a future regression on the rejection error
// surface fail in CI instead of in the next round of manual testing.

fn propose_cmd(bin: &Path, path: &Path) -> KeepCmd {
    KeepCmd::new(bin).path(path).args([
        "wallet",
        "propose",
        "--group",
        // any-string: validation fires before group_pubkey decoding.
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--relay",
        "wss://relay.example.com",
        "--recovery",
        "2of3@6mo",
    ])
}

#[test]
fn test_wallet_propose_rejects_zero_timeout() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("vault");

    let output = propose_cmd(&bin, &vault)
        .args(["--network", "signet", "--timeout", "0"])
        .run();
    assert_failure(&output);
    assert!(
        output_contains(&output, "timeout must be between"),
        "expected timeout boundary error, got: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_wallet_propose_rejects_oversize_timeout() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("vault");

    let output = propose_cmd(&bin, &vault)
        .args(["--network", "signet", "--timeout", "86401"])
        .run();
    assert_failure(&output);
    assert!(
        output_contains(&output, "timeout must be between"),
        "expected timeout boundary error"
    );
}

#[test]
fn test_wallet_propose_rejects_unknown_network() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("vault");

    let output = propose_cmd(&bin, &vault)
        .args(["--network", "fakenet"])
        .run();
    assert_failure(&output);
    assert!(
        output_contains(&output, "Invalid network"),
        "expected unknown-network rejection, got: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_wallet_propose_accepts_every_canonical_network() {
    // Mirror of `parse_network`'s positive cases (#428) so the wallet-propose
    // surface gates them the same way as the bitcoin subcommands. We expect
    // the network check to PASS and the command to fail later on vault open,
    // proving the early `Invalid network` gate let the input through.
    let bin = require_binary!();

    for network in ["bitcoin", "testnet", "signet", "regtest"] {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("vault");

        let output = propose_cmd(&bin, &vault).args(["--network", network]).run();
        assert_failure(&output); // vault doesn't exist
                                 // The failure MUST NOT be on the network check; it must surface from
                                 // a later step (vault open / missing file).
        assert!(
            !output_contains(&output, "Invalid network"),
            "network {network:?} must pass the early validation gate"
        );
    }
}

// -----------------------------------------------------------------------------
// #434 Area 3: backup / restore round-trip (vault data-integrity safety net)
//
// With KEEP_PASSWORD set by the harness, both the vault unlock AND the backup
// passphrase (and, on restore, the new vault password) are non-interactive, so
// the whole round trip runs unattended. `restore` takes the backup file
// positionally and a mandatory `--target` (a NEW path it refuses to overwrite).
// -----------------------------------------------------------------------------

/// A full-vault backup restored into a fresh path preserves every stored key.
#[test]
fn test_backup_restore_round_trip_preserves_keys() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("src-vault");
    let backup = dir.path().join("vault.kbak");
    let restored = dir.path().join("restored-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "alpha"])
            .run(),
    );
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "beta"])
            .run(),
    );

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["backup", "--output", backup.to_str().unwrap()])
        .run();
    assert_success(&out);
    assert!(backup.exists(), "backup file must be written");

    let out = KeepCmd::new(&bin)
        .args([
            "restore",
            backup.to_str().unwrap(),
            "--target",
            restored.to_str().unwrap(),
        ])
        .run();
    assert_success(&out);

    let out = KeepCmd::new(&bin).path(&restored).args(["list"]).run();
    assert_success(&out);
    assert!(output_contains(&out, "alpha"));
    assert!(output_contains(&out, "beta"));
}

/// A restored vault's FROST group still produces a valid BIP-340 signature,
/// proving the key package (not just metadata) survived the round trip.
#[test]
fn test_backup_restore_preserves_frost_group_signing() {
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    use keep_core::Keep;

    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("src-vault");
    let backup = dir.path().join("vault.kbak");
    let restored = dir.path().join("restored-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args([
                "frost",
                "generate",
                "--threshold",
                "2",
                "--shares",
                "3",
                "--name",
                "grp",
            ])
            .run(),
    );
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["backup", "--output", backup.to_str().unwrap()])
            .run(),
    );
    assert_success(
        &KeepCmd::new(&bin)
            .args([
                "restore",
                backup.to_str().unwrap(),
                "--target",
                restored.to_str().unwrap(),
            ])
            .run(),
    );

    // Read the group pubkey from the RESTORED vault (the display npub is truncated).
    let group_pubkey: [u8; 32] = {
        let mut keep = Keep::open(&restored).unwrap();
        keep.unlock(TEST_PASSWORD).unwrap();
        let shares = keep.frost_list_shares().unwrap();
        shares
            .iter()
            .find(|s| s.metadata.name == "grp")
            .expect("group must survive restore")
            .metadata
            .group_pubkey
    };

    let digest: [u8; 32] = sha2::Sha256::digest(b"restored group signing payload").into();
    let msg_hex = hex::encode(digest);
    let sign_out = KeepCmd::new(&bin)
        .path(&restored)
        .args(["frost", "sign", "--message", &msg_hex, "--group", "grp"])
        .run();
    assert_success(&sign_out);

    let sig = extract_signature_hex(&sign_out);
    let signature = schnorr::Signature::from_slice(&sig).expect("valid schnorr signature");
    let msg = Message::from_digest(digest);
    let xonly = XOnlyPublicKey::from_slice(&group_pubkey).expect("group pubkey x-only");
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &msg, &xonly)
        .expect("a restored FROST group's signature MUST verify against the group pubkey");
}

/// `restore` refuses to write over an existing path, so it can never clobber a
/// live vault.
#[test]
fn test_restore_refuses_existing_target() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("src-vault");
    let backup = dir.path().join("vault.kbak");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["backup", "--output", backup.to_str().unwrap()])
            .run(),
    );

    // Target = the existing source vault: restore MUST refuse.
    let out = KeepCmd::new(&bin)
        .args([
            "restore",
            backup.to_str().unwrap(),
            "--target",
            vault.to_str().unwrap(),
        ])
        .run();
    assert_failure(&out);
}

/// Restoring with the wrong backup passphrase fails cleanly and leaves no vault.
#[test]
fn test_restore_wrong_passphrase_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("src-vault");
    let backup = dir.path().join("vault.kbak");
    let restored = dir.path().join("restored-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["backup", "--output", backup.to_str().unwrap()])
            .run(),
    );

    // Restore reads the backup passphrase from KEEP_PASSWORD; override it with a
    // wrong (but length-valid) value so failure is at decryption, not validation.
    let out = KeepCmd::new(&bin)
        .env("KEEP_PASSWORD", "wrongpassword123")
        .args([
            "restore",
            backup.to_str().unwrap(),
            "--target",
            restored.to_str().unwrap(),
        ])
        .run();
    assert_failure(&out);
    assert!(
        !restored.exists(),
        "a failed restore must not leave a partial vault"
    );
}

/// A single-byte tamper of the backup's AEAD tag is caught on restore.
#[test]
fn test_restore_rejects_tampered_backup() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("src-vault");
    let backup = dir.path().join("vault.kbak");
    let restored = dir.path().join("restored-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["backup", "--output", backup.to_str().unwrap()])
            .run(),
    );

    // Flip the final byte (inside the AEAD tag) so authentication fails.
    let mut bytes = std::fs::read(&backup).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&backup, &bytes).unwrap();

    let out = KeepCmd::new(&bin)
        .args([
            "restore",
            backup.to_str().unwrap(),
            "--target",
            restored.to_str().unwrap(),
        ])
        .run();
    assert_failure(&out);
    assert!(
        !restored.exists(),
        "a tampered restore must not leave a vault"
    );
}

// -----------------------------------------------------------------------------
// #434 Area 4: rotate-password / rotate-data-key / frost refresh
// (security-critical vault mutations)
// -----------------------------------------------------------------------------

/// Read a named FROST group's pubkey directly from the vault (the display npub
/// is truncated, so parse it in-process).
fn frost_group_pubkey(vault: &Path, name: &str) -> [u8; 32] {
    use keep_core::Keep;
    let mut keep = Keep::open(vault).unwrap();
    keep.unlock(TEST_PASSWORD).unwrap();
    let shares = keep.frost_list_shares().unwrap();
    shares
        .iter()
        .find(|s| s.metadata.name == name)
        .unwrap_or_else(|| panic!("group {name} not found"))
        .metadata
        .group_pubkey
}

/// Assert `frost sign` output is a BIP-340 signature valid for `group_pubkey`
/// over `digest`.
fn assert_frost_sig_verifies(output: &Output, group_pubkey: &[u8; 32], digest: [u8; 32]) {
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let sig = extract_signature_hex(output);
    let signature = schnorr::Signature::from_slice(&sig).expect("valid schnorr signature");
    let msg = Message::from_digest(digest);
    let xonly = XOnlyPublicKey::from_slice(group_pubkey).expect("group pubkey x-only");
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &msg, &xonly)
        .expect("`frost sign` output MUST verify against the group pubkey via BIP-340");
}

/// Rotating the vault password swaps the unlock credential: the new password
/// unlocks and the old one no longer does.
#[test]
fn test_rotate_password_changes_unlock_credential() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("rot-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    // Old password from KEEP_PASSWORD, new from KEEP_NEW_PASSWORD (KEEP_YES
    // auto-confirms the re-encryption prompt).
    let out = KeepCmd::new(&bin)
        .path(&vault)
        .env("KEEP_NEW_PASSWORD", "newpass456789")
        .args(["rotate-password"])
        .run();
    assert_success(&out);

    // New password unlocks.
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .env("KEEP_PASSWORD", "newpass456789")
            .args(["list"])
            .run(),
    );
    // Old password no longer unlocks.
    assert_failure(&KeepCmd::new(&bin).path(&vault).args(["list"]).run());
}

/// Rotating to an identical password is refused (a no-op rotation), and the
/// original credential keeps working (no partial application).
#[test]
fn test_rotate_password_rejects_identical_password() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("rot-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .env("KEEP_NEW_PASSWORD", TEST_PASSWORD)
        .args(["rotate-password"])
        .run();
    assert_failure(&out);

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["list"]).run());
}

/// Rotating the data key re-encrypts every stored key/share but must not change
/// the FROST group key, and the group must still sign.
#[test]
fn test_rotate_data_key_preserves_frost_signing() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("rdk-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args([
                "frost",
                "generate",
                "--threshold",
                "2",
                "--shares",
                "3",
                "--name",
                "grp",
            ])
            .run(),
    );
    let group_pubkey = frost_group_pubkey(&vault, "grp");

    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["rotate-data-key"])
            .run(),
    );

    assert_eq!(
        frost_group_pubkey(&vault, "grp"),
        group_pubkey,
        "data-key rotation must not change the group key"
    );
    let digest: [u8; 32] = sha2::Sha256::digest(b"post-rotation signing payload").into();
    let sign_out = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            &hex::encode(digest),
            "--group",
            "grp",
        ])
        .run();
    assert_success(&sign_out);
    assert_frost_sig_verifies(&sign_out, &group_pubkey, digest);
}

/// A proactive `frost refresh` issues new shares but preserves the group key,
/// and the refreshed shares still reconstruct a valid signature.
#[test]
fn test_frost_refresh_preserves_group_signing() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("refresh-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args([
                "frost",
                "generate",
                "--threshold",
                "2",
                "--shares",
                "3",
                "--name",
                "grp",
            ])
            .run(),
    );
    let group_pubkey = frost_group_pubkey(&vault, "grp");

    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["frost", "refresh", "--group", "grp"])
            .run(),
    );
    assert_eq!(
        frost_group_pubkey(&vault, "grp"),
        group_pubkey,
        "refresh must preserve the group key"
    );

    let digest: [u8; 32] = sha2::Sha256::digest(b"post-refresh signing payload").into();
    let sign_out = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "frost",
            "sign",
            "--message",
            &hex::encode(digest),
            "--group",
            "grp",
        ])
        .run();
    assert_success(&sign_out);
    assert_frost_sig_verifies(&sign_out, &group_pubkey, digest);
}

// -----------------------------------------------------------------------------
// #434 Area 7: audit verify / stats / retention (tamper-evident audit log)
// -----------------------------------------------------------------------------

/// `audit verify` confirms the hash chain of a genuine, unmodified log.
#[test]
fn test_audit_verify_passes_on_intact_log() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("audit-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["audit", "verify"])
        .run();
    assert_success(&out);
    assert!(output_contains(&out, "verified"));
}

/// `audit verify` MUST detect a post-hoc modification of the audit log: the
/// tamper-evidence guarantee. Flipping a single byte breaks either an entry's
/// AEAD tag or the hash chain, and the command exits non-zero.
#[test]
fn test_audit_verify_detects_tampering() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("audit-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    // Verify passes before tampering.
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["audit", "verify"])
            .run(),
    );

    // Flip a byte inside the encrypted, hash-chained log.
    let log = vault.join("audit.log");
    let mut bytes = std::fs::read(&log).expect("audit log must exist");
    assert!(bytes.len() > 4, "audit log should have content");
    let idx = bytes.len() / 2;
    bytes[idx] ^= 0xff;
    std::fs::write(&log, &bytes).unwrap();

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["audit", "verify"])
        .run();
    assert_failure(&out);
}

/// `audit stats` reports the count of each event type; two `generate`s show as
/// two key generations.
#[test]
fn test_audit_stats_counts_key_generation() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("audit-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    for name in ["k1", "k2"] {
        assert_success(
            &KeepCmd::new(&bin)
                .path(&vault)
                .args(["generate", "--name", name])
                .run(),
        );
    }

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["audit", "stats"])
        .run();
    assert_success(&out);
    assert!(output_contains(&out, "Generated: 2"));
}

/// `audit retention --apply` is refused without a policy bound (it must never
/// guess), and a bound without `--apply` reports a dry run rather than deleting.
#[test]
fn test_audit_retention_apply_requires_policy_bound() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("audit-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    // --apply with no bound: refused.
    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["audit", "retention", "--apply"])
        .run();
    assert_failure(&out);

    // A bound without --apply: dry run, nothing deleted.
    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["audit", "retention", "--max-entries", "5"])
        .run();
    assert_success(&out);
    assert!(output_contains(&out, "NOT applied"));
}

// -----------------------------------------------------------------------------
// #434 Area 5: bitcoin address / descriptor (BIP-86 Taproot derivation)
// -----------------------------------------------------------------------------

/// Extract the address printed on the `Index <index>:` line of `bitcoin address`
/// output (`out.info` writes to stderr; check both streams).
fn extract_address_at(output: &Output, index: u32) -> String {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let needle = format!("Index {index}: ");
    for line in combined.lines() {
        if let Some(pos) = line.find(&needle) {
            return line[pos + needle.len()..].trim().to_string();
        }
    }
    panic!("no 'Index {index}:' line in output:\n{combined}");
}

/// `bitcoin address` derives a BIP-86 Taproot address whose HRP matches the
/// requested network (mainnet -> bc1p, testnet -> tb1p).
#[test]
fn test_bitcoin_address_taproot_per_network() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("btc-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    let testnet = KeepCmd::new(&bin)
        .path(&vault)
        .args(["bitcoin", "address", "--key", "k", "--network", "testnet"])
        .run();
    assert_success(&testnet);
    assert!(output_contains(&testnet, "tb1p"), "testnet taproot HRP");

    let mainnet = KeepCmd::new(&bin)
        .path(&vault)
        .args(["bitcoin", "address", "--key", "k", "--network", "mainnet"])
        .run();
    assert_success(&mainnet);
    assert!(output_contains(&mainnet, "bc1p"), "mainnet taproot HRP");
}

/// BIP-86 derivation is deterministic (same key+index -> same address) and each
/// index yields a distinct address.
#[test]
fn test_bitcoin_address_is_deterministic_per_index() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("btc-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    let addr_cmd = |bin: &Path, vault: &Path| {
        KeepCmd::new(bin)
            .path(vault)
            .args([
                "bitcoin",
                "address",
                "--key",
                "k",
                "--count",
                "3",
                "--network",
                "testnet",
            ])
            .run()
    };

    let first = addr_cmd(&bin, &vault);
    let second = addr_cmd(&bin, &vault);
    // Same index reproduces the same address across runs.
    assert_eq!(
        extract_address_at(&first, 0),
        extract_address_at(&second, 0),
        "BIP-86 derivation must be deterministic"
    );
    // Distinct indexes yield distinct addresses.
    let a0 = extract_address_at(&first, 0);
    let a1 = extract_address_at(&first, 1);
    let a2 = extract_address_at(&first, 2);
    assert_ne!(a0, a1);
    assert_ne!(a1, a2);
    assert_ne!(a0, a2);
    assert!(a0.starts_with("tb1p"));
}

/// `bitcoin descriptor` exports a BIP-86 `tr(...)` output descriptor.
#[test]
fn test_bitcoin_descriptor_is_taproot() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("btc-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "bitcoin",
            "descriptor",
            "--key",
            "k",
            "--network",
            "testnet",
        ])
        .run();
    assert_success(&out);
    assert!(output_contains(&out, "tr("), "BIP-86 taproot descriptor");
}

/// An unrecognized `--network` is rejected.
#[test]
fn test_bitcoin_rejects_invalid_network() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("btc-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "k"])
            .run(),
    );

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args([
            "bitcoin",
            "address",
            "--key",
            "k",
            "--network",
            "notanetwork",
        ])
        .run();
    assert_failure(&out);
}

// -----------------------------------------------------------------------------
// #434 Area 8: config (show/path/init) and migrate status
// -----------------------------------------------------------------------------

/// `config init` creates the config file, `path` prints its location, and `show`
/// renders the summary. The config home is isolated via HOME + XDG_CONFIG_HOME so
/// the test never touches the real user config; a second `init` refusing to
/// overwrite proves the file was created (path-agnostic across platforms).
#[test]
fn test_config_init_path_and_show_isolated() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let cfg_home = dir.path().join("config");
    let home = dir.path().join("home");

    let cmd = |args: &[&str]| {
        KeepCmd::new(&bin)
            .env("XDG_CONFIG_HOME", cfg_home.to_str().unwrap())
            .env("HOME", home.to_str().unwrap())
            .args(args)
            .run()
    };

    // path prints a config.toml location.
    let out = cmd(&["config", "path"]);
    assert_success(&out);
    assert!(output_contains(&out, "config.toml"));

    // init creates it; a second init detects it already exists (so it now does).
    assert_success(&cmd(&["config", "init"]));
    let again = cmd(&["config", "init"]);
    assert_success(&again);
    assert!(output_contains(&again, "already exists"));

    // show renders the config summary.
    let out = cmd(&["config", "show"]);
    assert_success(&out);
    assert!(output_contains(&out, "Config file"));
}

/// `migrate status` on a freshly created vault reports the current schema and no
/// pending migration.
#[test]
fn test_migrate_status_fresh_vault_needs_no_migration() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("mig-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());

    let out = KeepCmd::new(&bin)
        .path(&vault)
        .args(["migrate", "status"])
        .run();
    assert_success(&out);
    assert!(output_contains(&out, "Needs migration"));
    assert!(output_contains(&out, "false"));
}

// -----------------------------------------------------------------------------
// #434 Area 1: NIP-46 bunker end-to-end (keep's core promise)
//
// Launch a headless `keep serve` bunker as a subprocess against an in-process
// mock relay, connect a real nostr client, request a signature over NIP-46, and
// verify the returned event's BIP-340 signature. This drives the whole CLI serve
// path end to end, not just the library.
// -----------------------------------------------------------------------------

/// A running `keep serve` child, killed on drop (headless serve never exits on
/// its own).
struct ServeChild {
    child: std::process::Child,
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `keep serve --headless` against `relay`, scrape the `bunker://` URL it
/// prints to stderr, and return the running child (killed on drop) plus the URL.
/// A reader thread drains stderr so the pipe never stalls the child.
fn spawn_bunker(bin: &Path, vault: &Path, relay: &str) -> (ServeChild, String) {
    use std::io::{BufRead, BufReader};
    let mut child = Command::new(bin)
        .env("KEEP_PASSWORD", TEST_PASSWORD)
        .env("KEEP_YES", "1")
        .env("KEEP_ALLOW_WS", "1") // accept the loopback ws:// mock relay
        .arg("--path")
        .arg(vault)
        .args(["serve", "--headless", "--relay", relay])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keep serve");

    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        let mut sent = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // child exited / stderr closed
                Ok(_) => {
                    if !sent {
                        if let Some(pos) = line.find("bunker://") {
                            let _ = tx.send(line[pos..].trim().to_string());
                            sent = true;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    let url = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("keep serve must print a bunker:// URL within 15s");
    (ServeChild { child }, url)
}

/// NIP-44-encrypt a `{id,method,params}` request and send it to the bunker as a
/// `Kind::NostrConnect` event.
async fn send_nip46(
    client: &nostr_sdk::Client,
    client_keys: &nostr_sdk::Keys,
    server_pubkey: &nostr_sdk::PublicKey,
    request: &serde_json::Value,
) {
    use nostr_sdk::prelude::*;
    let json = request.to_string();
    let encrypted = nip44::encrypt(
        client_keys.secret_key(),
        server_pubkey,
        &json,
        nip44::Version::V2,
    )
    .expect("nip44 encrypt");
    let event = EventBuilder::new(Kind::NostrConnect, &encrypted)
        .tag(Tag::public_key(*server_pubkey))
        .sign_with_keys(client_keys)
        .expect("sign nip46 request");
    client.send_event(&event).await.expect("send_event");
}

/// Wait up to `timeout` for a decrypted NIP-46 response from the bunker whose
/// JSON `id` matches `expected_id`. `notifications` must be created BEFORE the
/// request is sent so a fast response cannot be dropped.
async fn await_nip46(
    notifications: &mut tokio::sync::broadcast::Receiver<nostr_sdk::RelayPoolNotification>,
    client_keys: &nostr_sdk::Keys,
    server_pubkey: &nostr_sdk::PublicKey,
    expected_id: &str,
    timeout: Duration,
) -> Option<serde_json::Value> {
    use nostr_sdk::prelude::*;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        let event = match tokio::time::timeout(remaining, notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => event,
            _ => continue,
        };
        if event.kind != Kind::NostrConnect || event.pubkey != *server_pubkey {
            continue;
        }
        let decrypted = match nip44::decrypt(
            client_keys.secret_key(),
            server_pubkey,
            event.content.as_str(),
        ) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let json: serde_json::Value = match serde_json::from_str(&decrypted) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if json.get("id").and_then(|v| v.as_str()) != Some(expected_id) {
            continue;
        }
        return Some(json);
    }
}

#[tokio::test]
async fn test_serve_bunker_e2e_sign_verifies() {
    use nostr_sdk::prelude::*;

    let bin = match keep_binary() {
        Some(b) => b,
        None => {
            eprintln!("SKIPPED: keep binary not found (build with: cargo build -p keep-cli)");
            return;
        }
    };

    // Required once before any nostr/TLS client work.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("bunker-vault");

    // A single-key vault: `keep serve` runs in single-key mode and signs with it.
    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["generate", "--name", "signer"])
            .run(),
    );

    let mock = nostr_relay_builder::MockRelay::run()
        .await
        .expect("mock relay start");
    let relay_url = mock.url().await.to_string();

    // Launch the headless bunker against the mock relay and read its bunker:// URL.
    let (_serve, bunker_url) = spawn_bunker(&bin, &vault, &relay_url);
    let parsed = url::Url::parse(&bunker_url).expect("bunker url parses");
    let server_pubkey =
        PublicKey::from_hex(parsed.host_str().expect("bunker host")).expect("server pubkey");
    let secret = parsed
        .query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();

    // The URL is printed before the bunker finishes subscribing on the relay.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client_keys = Keys::generate();
    let client = Client::new(client_keys.clone());
    client.add_relay(&relay_url).await.unwrap();
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    client
        .subscribe(
            Filter::new()
                .kind(Kind::NostrConnect)
                .author(server_pubkey)
                .pubkey(client_keys.public_key()),
            None,
        )
        .await
        .expect("subscribe to bunker responses");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut notifications = client.notifications();

    // 1. connect -> ack
    let connect_req = serde_json::json!({
        "id": "req-connect",
        "method": "connect",
        "params": [server_pubkey.to_hex(), secret],
    });
    send_nip46(&client, &client_keys, &server_pubkey, &connect_req).await;
    let ack = await_nip46(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-connect",
        Duration::from_secs(10),
    )
    .await
    .expect("connect must respond");
    assert_eq!(
        ack.get("result").and_then(|v| v.as_str()),
        Some("ack"),
        "connect must ack, got {ack}"
    );

    // 2. get_public_key -> the key the bunker will sign with
    let gpk_req = serde_json::json!({"id": "req-gpk", "method": "get_public_key", "params": []});
    send_nip46(&client, &client_keys, &server_pubkey, &gpk_req).await;
    let gpk = await_nip46(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-gpk",
        Duration::from_secs(10),
    )
    .await
    .expect("get_public_key must respond");
    let signer_hex = gpk
        .get("result")
        .and_then(|v| v.as_str())
        .expect("get_public_key result")
        .to_string();

    // 3. sign_event -> a signed kind-1 note that MUST verify
    let request_content = "keep serve bunker e2e signing payload";
    let unsigned = serde_json::json!({
        "kind": 1,
        "content": request_content,
        "tags": [],
        "created_at": Timestamp::now().as_secs(),
    });
    let sign_req = serde_json::json!({
        "id": "req-sign",
        "method": "sign_event",
        "params": [serde_json::to_string(&unsigned).unwrap()],
    });
    send_nip46(&client, &client_keys, &server_pubkey, &sign_req).await;
    let resp = await_nip46(
        &mut notifications,
        &client_keys,
        &server_pubkey,
        "req-sign",
        Duration::from_secs(10),
    )
    .await
    .expect("sign_event must respond");

    let result_str = resp
        .get("result")
        .and_then(|v| v.as_str())
        .expect("sign_event response must include result");
    let signed = Event::from_json(result_str).expect("result is a JSON-stringified signed event");

    // verify() recomputes the id and checks the BIP-340 signature + pubkey binding.
    signed.verify().expect("returned event MUST verify");
    assert_eq!(
        signed.content, request_content,
        "content must match request"
    );
    assert_eq!(signed.kind, Kind::TextNote, "kind must match request");
    assert_eq!(
        signed.pubkey.to_hex(),
        signer_hex,
        "event must be signed under the bunker's signer key"
    );

    client.disconnect().await;
    drop(mock); // keep the relay alive until the flow completes
}
