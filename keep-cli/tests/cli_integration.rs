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
                eprintln!("SKIPPED: keep binary not found (build with: cargo build -p keep-cli)");
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
        cmd.env("KEEP_TESTING_MODE", "1");
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
        self.cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
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

    let output = KeepCmd::new(&bin)
        .path(&vault)
        .args(["export", "--name", "testkey"])
        .run();
    assert_success(&output);
    assert!(output_contains(&output, "nsec1"));
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

#[test]
fn test_import_export_nsec_roundtrip() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault1 = dir.path().join("vault1");
    let vault2 = dir.path().join("vault2");

    assert_success(&KeepCmd::new(&bin).path(&vault1).args(["init"]).run());
    assert_success(
        &KeepCmd::new(&bin)
            .path(&vault1)
            .args(["generate", "--name", "original"])
            .run(),
    );

    let output = KeepCmd::new(&bin)
        .path(&vault1)
        .args(["export", "--name", "original"])
        .run();
    assert_success(&output);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let nsec = combined
        .lines()
        .find(|l| l.trim().starts_with("nsec1"))
        .expect("no nsec found in output")
        .trim();

    assert_success(&KeepCmd::new(&bin).path(&vault2).args(["init"]).run());

    let output = KeepCmd::new(&bin)
        .path(&vault2)
        .env("KEEP_NSEC", nsec)
        .args(["import", "--name", "imported"])
        .run();
    assert_success(&output);

    let output = KeepCmd::new(&bin).path(&vault2).args(["list"]).run();
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

#[test]
fn test_export_nonexistent_key_fails() {
    let bin = require_binary!();
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("nokey-vault");

    assert_success(&KeepCmd::new(&bin).path(&vault).args(["init"]).run());
    assert_failure(
        &KeepCmd::new(&bin)
            .path(&vault)
            .args(["export", "--name", "nonexistent"])
            .run(),
    );
}

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
