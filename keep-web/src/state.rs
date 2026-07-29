use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

use keep_core::Keep;
use keep_frost_net::KfpNode;

/// How long a single-use WebSocket ticket stays valid after issue.
const WS_TICKET_TTL: Duration = Duration::from_secs(30);

/// Single-use, short-lived tickets authorizing one WebSocket upgrade. Browsers
/// can't set headers on a `WebSocket`, so instead of putting the durable bearer
/// token in the URL (where reverse-proxy access logs would capture it), an
/// authed client mints a ticket and passes that; it is consumed on first use.
#[derive(Clone, Default)]
pub struct TicketStore(Arc<StdMutex<HashMap<String, Instant>>>);

impl TicketStore {
    /// Records a freshly minted ticket, pruning any that have expired.
    pub fn issue(&self, ticket: String) {
        if let Ok(mut map) = self.0.lock() {
            let now = Instant::now();
            map.retain(|_, issued| now.duration_since(*issued) < WS_TICKET_TTL);
            map.insert(ticket, now);
        }
    }

    /// Consumes a ticket, returning true only if it was present and unexpired.
    pub fn consume(&self, ticket: &str) -> bool {
        match self.0.lock() {
            Ok(mut map) => map
                .remove(ticket)
                .is_some_and(|issued| issued.elapsed() < WS_TICKET_TTL),
            Err(_) => false,
        }
    }
}

/// Shared application state handed to every axum handler.
#[derive(Clone)]
pub struct AppState {
    /// Unlocked vault, used for read-only queries (share listing, etc.).
    pub keep: Arc<Mutex<Keep>>,
    /// Bunker connection details, populated once the server is up.
    pub bunker: BunkerInfo,
    /// Identifier of the share the running co-signer loaded (network mode), so
    /// the delete guard can block exactly that share without false positives.
    pub active_identifier: Option<u16>,
    /// Live event stream (logs + approval requests) for WebSocket clients.
    pub events: broadcast::Sender<Event>,
    /// Pending approval requests awaiting a browser decision, keyed by id.
    pub approvals: Arc<StdMutex<HashMap<u64, Sender<bool>>>>,
    /// Single-use WebSocket upgrade tickets.
    pub ws_tickets: TicketStore,
    /// Kill switch: when false, the co-signer refuses to participate. Toggled
    /// live (no restart); the policy hook reads it on every round.
    pub signing_enabled: Arc<AtomicBool>,
    /// Latched once the operator deletes the share the live node loaded. The
    /// node still holds that share in memory, so co-signing is force-disabled
    /// and cannot be re-enabled until a restart re-resolves shares from disk.
    pub signer_retired: Arc<AtomicBool>,
    /// Where the kill-switch state is persisted, so a live toggle survives a
    /// restart instead of reverting to a boot default.
    pub signing_flag_path: PathBuf,
    /// The running FROST node (network mode only), for reading the signing
    /// audit log and peer state.
    pub node: Option<Arc<KfpNode>>,
    /// Single-flight latch for active-group switches. Once a switch is claimed,
    /// the node is on its way to exiting/restarting, so a second concurrent
    /// switch is rejected rather than racing to persist a different key.
    pub switching: Arc<AtomicBool>,
}

#[derive(Clone, Serialize)]
pub struct BunkerInfo {
    /// "network-frost" (always-on co-signer) or "single-key" (fallback).
    pub mode: String,
    pub url: String,
    pub npub: String,
    /// NIP-46 bunker transport relays.
    pub bunker_relays: Vec<String>,
    /// FROST peer-coordination relays (network mode only).
    pub frost_relays: Vec<String>,
    /// Group npub this node co-signs for (network mode only).
    pub group: Option<String>,
    /// Threshold as "t-of-n" (network mode only).
    pub threshold: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_single_use() {
        let store = TicketStore::default();
        store.issue("abc".into());
        assert!(store.consume("abc"));
        // Second use is rejected.
        assert!(!store.consume("abc"));
    }

    #[test]
    fn unknown_ticket_rejected() {
        let store = TicketStore::default();
        assert!(!store.consume("nope"));
        store.issue("abc".into());
        assert!(!store.consume("def"));
    }

    #[test]
    fn auth_token_is_generated_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_auth_token(dir.path()).unwrap();
        assert_eq!(first.len(), 64, "32 random bytes, hex encoded");

        // Stable across restarts and upgrades: an operator's token must not be
        // invalidated by a service restart.
        let second = load_or_create_auth_token(dir.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn sweep_removes_stale_temp_debris_but_spares_the_token_and_fresh_temps() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("auth_token");
        std::fs::write(&token, "live").unwrap();
        let debris = dir.path().join("auth_token.tmp.123.deadbeef");
        std::fs::write(&debris, "orphan").unwrap();
        let unrelated = dir.path().join("keep.db");
        std::fs::write(&unrelated, "data").unwrap();

        // min_age 0: the temp (any age) is swept; the live token and unrelated
        // files (which do not match the `<name>.tmp.` prefix) are untouched.
        sweep_stale_temp_files(&token, std::time::Duration::ZERO);
        assert!(token.exists(), "the live token must never be swept");
        assert!(!debris.exists(), "stale temp debris must be swept");
        assert!(unrelated.exists(), "unrelated files must not be swept");

        // A fresh temp is spared when it is younger than min_age: a concurrent
        // writer's in-flight temp is not deleted out from under its rename.
        let fresh = dir.path().join("auth_token.tmp.456.cafef00d");
        std::fs::write(&fresh, "in-flight").unwrap();
        sweep_stale_temp_files(&token, std::time::Duration::from_secs(3600));
        assert!(fresh.exists(), "a temp younger than min_age must be spared");
    }

    #[test]
    fn bunker_secret_first_writer_wins_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_bunker_secret(dir.path()).unwrap();
        assert_eq!(first.len(), 32, "16 random bytes, hex encoded");
        // A second call (as a race loser or a restart would) reads the winner's
        // secret rather than minting a divergent one.
        let second = load_or_create_bunker_secret(dir.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn bunker_secret_rejects_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bunker_secret"), "short-and-not-hex").unwrap();
        assert!(
            load_or_create_bunker_secret(dir.path()).is_err(),
            "a truncated/malformed secret must fail closed, not be served"
        );
    }

    #[test]
    fn transport_key_first_writer_wins_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_transport_key(dir.path()).unwrap();
        let second = load_or_create_transport_key(dir.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn transport_key_rejects_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bunker_transport_key"), "deadbeef").unwrap();
        assert!(
            load_or_create_transport_key(dir.path()).is_err(),
            "a truncated/malformed key must fail closed"
        );
    }

    #[test]
    fn bunker_credentials_reject_empty_file() {
        // The phantom-window case: a winner creates the file before writing, and a
        // concurrent loser reads it empty. An empty file must fail closed, never
        // be served, for both credentials.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bunker_secret"), "").unwrap();
        assert!(load_or_create_bunker_secret(dir.path()).is_err());
        std::fs::write(dir.path().join("bunker_transport_key"), "").unwrap();
        assert!(load_or_create_transport_key(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bunker_secret_rejects_symlink() {
        // A planted symlink in the vault dir must not be followed to an
        // attacker-chosen target, matching the auth-token reader.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "a".repeat(32)).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("bunker_secret")).unwrap();
        assert!(
            load_or_create_bunker_secret(dir.path()).is_err(),
            "a symlinked bunker_secret must be refused, not followed"
        );
    }

    #[test]
    fn choose_persist_path_prefers_state_dir_outside_vault() {
        let vault = Path::new("/data");
        let state = Path::new("/var/lib/keep-web");
        // A state directory is preferred and reported as outside the vault.
        let (path, in_vault) = choose_persist_path(Some(state), vault);
        assert_eq!(path, Path::new("/var/lib/keep-web/auth_token"));
        assert!(!in_vault);
        // No state directory falls back to the vault dir and flags it.
        let (path, in_vault) = choose_persist_path(None, vault);
        assert_eq!(path, Path::new("/data/auth_token"));
        assert!(in_vault);
        // An empty state directory is treated as absent.
        let (_, in_vault) = choose_persist_path(Some(Path::new("")), vault);
        assert!(in_vault);
        // A state directory equal to the vault dir is not "outside" it: flag it so
        // the backup warning still fires.
        let (path, in_vault) = choose_persist_path(Some(vault), vault);
        assert_eq!(path, Path::new("/data/auth_token"));
        assert!(in_vault);
        // A state dir NESTED inside the vault is still in the backup path.
        let (_, in_vault) = choose_persist_path(Some(Path::new("/data/state")), vault);
        assert!(in_vault);
        // A state dir that is a PARENT of the vault is genuinely outside it (the
        // packaged /var/lib/keep-web vs vault /var/lib/keep-web/vault).
        let (path, in_vault) = choose_persist_path(
            Some(Path::new("/var/lib/keep-web")),
            Path::new("/var/lib/keep-web/vault"),
        );
        assert_eq!(path, Path::new("/var/lib/keep-web/auth_token"));
        assert!(!in_vault);
    }

    #[test]
    fn resolve_adopts_existing_vault_token_without_rotating() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        // An existing deployment already generated a token in the vault dir.
        let existing = load_or_create_auth_token_at(&vault.path().join("auth_token")).unwrap();

        // Upgrading into a state directory must ADOPT that token (never rotate it,
        // which would 401 the operator) and migrate it out of the vault.
        let (token, path, in_vault) =
            resolve_persisted_auth_token(Some(state.path()), vault.path()).unwrap();
        assert_eq!(token, existing, "must not rotate the operator's token");
        assert!(!in_vault);
        assert_eq!(path, state.path().join("auth_token"));
        assert!(path.exists(), "token now lives outside the vault");
        assert!(
            !vault.path().join("auth_token").exists(),
            "the in-vault copy is removed so it stays out of backups"
        );

        // Stable on the next start.
        let (again, _, _) = resolve_persisted_auth_token(Some(state.path()), vault.path()).unwrap();
        assert_eq!(again, existing);
    }

    #[test]
    fn resolve_mints_fresh_outside_vault_when_no_legacy_token() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (token, path, in_vault) =
            resolve_persisted_auth_token(Some(state.path()), vault.path()).unwrap();
        assert_eq!(token.len(), 64);
        assert!(!in_vault);
        assert_eq!(path, state.path().join("auth_token"));
        assert!(
            !vault.path().join("auth_token").exists(),
            "nothing written into the vault directory"
        );
    }

    #[test]
    fn auth_token_persists_outside_the_vault_directory() {
        // The generated token must live at the chosen path (a state dir), not in
        // the vault dir, and remain stable across restarts.
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (path, in_vault) = choose_persist_path(Some(state.path()), vault.path());
        assert!(!in_vault);

        let first = load_or_create_auth_token_at(&path).unwrap();
        assert_eq!(first.len(), 64);
        assert!(path.exists(), "token written to the state dir");
        assert!(
            !vault.path().join("auth_token").exists(),
            "nothing written into the vault directory"
        );
        let second = load_or_create_auth_token_at(&path).unwrap();
        assert_eq!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn auth_token_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_auth_token(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("auth_token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Writes a token file at 0600 so the mode gate does not mask the check
    /// under test.
    fn write_token_file(dir: &Path, contents: &str) {
        let path = dir.join("auth_token");
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn empty_auth_token_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_token_file(dir.path(), "   \n");
        // Minting a replacement would silently invalidate the operator's token.
        let err = load_or_create_auth_token(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn malformed_auth_token_fails_closed() {
        // A truncated write or a partial restore must not become a short,
        // brute-forceable admin credential.
        for bad in [
            "deadbeef",
            &"z".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_token_file(dir.path(), bad);
            let err = load_or_create_auth_token(dir.path())
                .expect_err("expected malformed token to be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "input {bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_auth_token_is_refused() {
        // Otherwise a planted link makes the daemon adopt attacker-known file
        // contents as the admin bearer token.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("attacker_known");
        std::fs::write(&target, "a".repeat(64)).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("auth_token")).unwrap();

        let err = load_or_create_auth_token(dir.path())
            .expect_err("expected a symlinked token to be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_auth_token_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth_token");
        std::fs::write(&path, "a".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = load_or_create_auth_token(dir.path())
            .expect_err("expected a group-readable token to be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}

impl BunkerInfo {
    /// Not yet provisioned: the admin UI is served, but no bunker/co-signer is
    /// running. The operator imports a share, then restarts the service.
    pub fn setup() -> Self {
        Self {
            mode: "setup".into(),
            url: String::new(),
            npub: String::new(),
            bunker_relays: Vec::new(),
            frost_relays: Vec::new(),
            group: None,
            threshold: None,
        }
    }
}

/// File (inside the vault dir) holding the persisted kill-switch state.
pub fn signing_flag_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("signing_enabled")
}

/// Reads the persisted kill-switch state, or `None` if it was never set or is
/// unreadable (caller falls back to the boot default).
pub fn read_signing_flag(path: &Path) -> Option<bool> {
    match std::fs::read_to_string(path) {
        Ok(s) => match s.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Persists the kill-switch state so it survives a restart. Best-effort: a write
/// failure is logged, not surfaced, since the in-memory toggle still applies.
pub fn persist_signing_flag(path: &Path, enabled: bool) {
    if let Err(e) = std::fs::write(path, if enabled { "true" } else { "false" }) {
        tracing::warn!(error = %e, path = %path.display(), "failed to persist kill-switch state");
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a credential file, creating it `0600` on Unix. Propagates IO errors:
/// a credential that can't be persisted must fail startup, not silently rotate.
///
/// Writes to a sibling temp file, fsyncs, then atomically renames over the
/// target, so a crash mid-write cannot leave a truncated/empty credential that a
/// later boot would treat as missing and silently replace.
fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    // Per-write temp name (PID + random suffix) so a concurrent writer cannot
    // clobber an in-flight temp file before its rename.
    let suffix: [u8; 8] = try_random()?;
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), to_hex(&suffix)));

    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };

    // On any failure before the rename succeeds, remove the temp so a crash or
    // transient error cannot leave an unguessable, never-cleaned-up temp file.
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // fsync the parent directory so the rename itself is durable across a crash;
    // otherwise the file could survive while the directory entry is lost.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Age past which a `write_secret_file` temp sibling is treated as orphaned. A
/// live write renames its temp within milliseconds, so anything older was left by
/// a crash (SIGKILL between `create_new` and `rename`) and is safe to remove
/// without racing a concurrent writer's in-flight temp.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// Best-effort sweep of stale `<name>.tmp.*` debris left by an interrupted
/// `write_secret_file` (currently only reachable via `migrate_auth_token`, which
/// runs only when the token persists outside the vault, so the debris lands in the
/// state/persist dir). Such files never became the live credential, but they linger
/// at `0600` in that dir and every filesystem backup of it, looking exactly like a
/// credential to anyone auditing the directory. Only files older than `min_age` are
/// removed so a concurrent writer's fresh temp is never deleted mid-write. Errors
/// are ignored.
fn sweep_stale_temp_files(path: &Path, min_age: std::time::Duration) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return;
    };
    let prefix = format!("{name}.tmp.");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        if !fname.starts_with(&prefix) {
            continue;
        }
        let old_enough = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if old_enough {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Loads the persisted admin API token, generating and storing one (`0600`) on
/// first run. Kept on disk rather than logged: this token gates every `/api/*`
/// route including share export, and the journal is readable by the `adm` group
/// and routinely shipped off-box. Persisting it also keeps the operator's token
/// valid across restarts and upgrades.
/// Test convenience: persist the token directly in `vault_dir`. Production code
/// uses [`choose_persist_path`] + [`load_or_create_auth_token_at`] so the token
/// lands outside the vault directory.
#[cfg(test)]
fn load_or_create_auth_token(vault_dir: &Path) -> std::io::Result<String> {
    load_or_create_auth_token_at(&vault_dir.join("auth_token"))
}

/// Choose where to persist a generated admin token. Prefer a state directory
/// OUTSIDE the vault (systemd `StateDirectory=`, i.e. `$STATE_DIRECTORY`) so a
/// whole-directory vault backup (tar, rsync, VM/volume snapshot) does not carry
/// this share-equivalent credential. Fall back to the vault directory only as a
/// last resort. Returns `(path, is_in_vault_dir)` so the caller can warn when the
/// token lands in the backup path.
pub fn choose_persist_path(
    state_dir: Option<&Path>,
    vault_dir: &Path,
) -> (std::path::PathBuf, bool) {
    match state_dir {
        // A state dir that is the vault dir, or nested inside it, is not "outside"
        // the backup path: the token would still be swept into a vault snapshot.
        // `starts_with` is component-wise, so `/data/state` under vault `/data` is
        // caught, while a state dir that is a PARENT of the vault (the packaged
        // `/var/lib/keep-web` vs vault `/var/lib/keep-web/vault`) is correctly
        // treated as outside. Fall through to the vault case so the warning stays
        // honest rather than being suppressed.
        Some(dir) if !dir.as_os_str().is_empty() && !dir.starts_with(vault_dir) => {
            (dir.join("auth_token"), false)
        }
        _ => (vault_dir.join("auth_token"), true),
    }
}

/// Loads the persisted admin API token from `path`, generating and storing one
/// (`0600`) on first run. `path` should live outside the vault directory (see
/// [`choose_persist_path`]) so it is not swept into a vault backup.
pub fn load_or_create_auth_token_at(path: &Path) -> std::io::Result<String> {
    // Sweep stale write_secret_file temp debris (e.g. from an interrupted token
    // migration) so credential-shaped files do not accumulate in this token's
    // directory and its backups. Best-effort; runs on every startup that resolves
    // the token.
    sweep_stale_temp_files(path, STALE_TEMP_AGE);

    // Create-exclusive on the final path, so concurrent starts resolve to
    // first-writer-wins. A rename-based write is last-writer-wins, which for a
    // credential means the loser serves a token that exists on no disk and the
    // operator reads one the live process rejects.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            use std::io::Write;
            let bytes: [u8; 32] = try_random()?;
            let token = to_hex(&bytes);
            f.write_all(token.as_bytes())?;
            f.sync_all()?;
            return Ok(token);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    read_auth_token(path)
}

/// Resolve the persisted admin token for the no-configured-token path. Chooses a
/// location via [`choose_persist_path`], and when an outside-vault target is
/// selected but not yet populated, adopts a legacy `$KEEP_PATH/auth_token` if one
/// exists, migrating it out of the vault. This is what keeps an existing
/// deployment from silently rotating its admin token on upgrade (a rotated token
/// 401s the operator) while still moving the credential out of the backup path.
/// Returns `(token, path, is_in_vault_dir)`.
pub fn resolve_persisted_auth_token(
    state_dir: Option<&Path>,
    vault_dir: &Path,
) -> std::io::Result<(String, std::path::PathBuf, bool)> {
    let (target, in_vault) = choose_persist_path(state_dir, vault_dir);
    if !in_vault && !target.exists() {
        let legacy = vault_dir.join("auth_token");
        if legacy.exists() {
            migrate_auth_token(&legacy, &target)?;
        }
    }
    let token = load_or_create_auth_token_at(&target)?;
    Ok((token, target, in_vault))
}

/// Move an existing, validated token from `legacy` to `target` without rotating
/// it: read (and validate) the current token, write it atomically at `target`
/// (`0600`), then best-effort remove the vault copy so the credential leaves the
/// backup path. A malformed legacy token fails closed (the caller then mints a
/// fresh one at `target`). If `target` was created concurrently, the atomic write
/// simply overwrites with the same adopted value.
fn migrate_auth_token(legacy: &Path, target: &Path) -> std::io::Result<()> {
    let token = match read_auth_token(legacy) {
        Ok(t) => t,
        // A malformed/tampered legacy token is not worth preserving; leave it for
        // the caller to replace with a freshly minted token at `target`.
        Err(_) => return Ok(()),
    };
    write_secret_file(target, &token)?;
    if let Err(e) = std::fs::remove_file(legacy) {
        tracing::warn!(
            path = %legacy.display(),
            error = %e,
            "migrated the admin token out of the vault directory but could not remove the old \
             in-vault copy; delete it manually so it stays out of vault backups"
        );
    } else {
        tracing::info!(
            from = %legacy.display(),
            to = %target.display(),
            "migrated the persisted admin token out of the vault directory"
        );
    }
    Ok(())
}

/// Reads an existing token, refusing to follow a symlink and requiring the
/// exact shape this daemon mints. A planted symlink would otherwise make the
/// daemon adopt attacker-known file contents as the admin bearer token, and a
/// truncated or tampered file would otherwise become a short, brute-forceable
/// credential.
fn read_auth_token(path: &Path) -> std::io::Result<String> {
    // 32 random bytes, hex, minted by this daemon.
    read_hardened_hex_secret(path, 64, "auth_token")
}

/// Read a keep-web-minted hex secret from `path` with the hardening every
/// credential-equivalent file needs: reject a symlink or non-regular file at the
/// final component, require owner-only permissions, re-open and confirm the
/// opened file's inode/device match the stat (closing the lstat->open swap
/// window), and require exactly `expected_hex_len` hex characters so a truncated,
/// partially-restored, or tampered file fails closed rather than being served.
fn read_hardened_hex_secret(
    path: &Path,
    expected_hex_len: usize,
    label: &str,
) -> std::io::Result<String> {
    // symlink_metadata does not traverse the final component, so a planted link
    // is rejected rather than silently followed.
    let md = std::fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} must be a regular file, not a symlink"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{label} is group/world accessible; refusing to use it"),
            ));
        }
    }

    // The check above inspected the path; this opens it again, so the entry could
    // have been swapped for a symlink in between. metadata() on the handle is an
    // fstat of what was actually opened, so comparing identity across the two
    // closes that window without reaching for libc.
    let mut f = std::fs::File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = f.metadata()?;
        if opened.ino() != md.ino() || opened.dev() != md.dev() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{label} changed while being read; refusing to use it"),
            ));
        }
    }

    use std::io::Read;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let trimmed = s.trim();
    if trimmed.len() != expected_hex_len || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} is malformed; expected {expected_hex_len} hex characters"),
        ));
    }
    Ok(trimmed.to_string())
}

/// Loads the persisted NIP-46 bunker secret, generating and storing one (`0600`)
/// on first run. Must be stable so the advertised bunker URL (which embeds it)
/// doesn't change across restarts. A write failure is propagated so startup
/// fails rather than rotating to an ephemeral secret that breaks saved clients.
/// Create `path` exclusively (`0600` on Unix) for first-writer-wins semantics:
/// two concurrent starts on the same vault dir cannot each mint a different
/// secret (the loser would serve an in-memory value disagreeing with disk).
/// Returns `Some(file)` when we created it (the caller writes the generated
/// secret), or `None` when it already existed (the caller re-reads the winner's).
fn create_secret_file_exclusive(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e),
    }
}

/// CSPRNG bytes for a credential, propagating a health-check failure as an error
/// rather than panicking (these loaders return `io::Result`, so startup fails
/// cleanly instead of aborting the process).
fn try_random<const N: usize>() -> std::io::Result<[u8; N]> {
    keep_core::crypto::try_random_bytes::<N>().map_err(|e| std::io::Error::other(e.to_string()))
}

/// Best-effort fsync of a path's parent directory so a freshly created entry is
/// durable across a crash; without it the entry can be lost and the secret
/// regenerated (rotating the bunker identity) on the next boot.
fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

pub fn load_or_create_bunker_secret(vault_dir: &Path) -> std::io::Result<String> {
    let path = vault_dir.join("bunker_secret");
    // First-writer-wins on the final path: create-exclusive rather than
    // read-then-write-via-rename, so concurrent starts cannot mint divergent
    // bunker secrets (which would advertise different bunker URLs).
    if let Some(mut f) = create_secret_file_exclusive(&path)? {
        use std::io::Write;
        let bytes = try_random::<16>()?;
        let secret = to_hex(&bytes);
        f.write_all(secret.as_bytes())?;
        f.sync_all()?;
        fsync_parent_dir(&path);
        return Ok(secret);
    }
    // Lost the race, or a normal restart: read the winner's secret through the
    // same hardened reader as the auth token (symlink/perm/inode guards + exact
    // 16-byte hex shape), so a truncated write, tamper, or planted symlink fails
    // closed rather than being served as a credential.
    read_hardened_hex_secret(&path, 32, "bunker_secret")
}

/// Loads the persisted NIP-46 transport key (the bunker URL's own identity),
/// generating and storing one (`0600`) on first run. Must be stable so the
/// bunker URL's pubkey doesn't change across restarts and saved client
/// connections keep working.
pub fn load_or_create_transport_key(vault_dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = vault_dir.join("bunker_transport_key");
    // First-writer-wins on the final path (see load_or_create_bunker_secret): a
    // divergent transport key across concurrent starts would change the bunker
    // URL's pubkey and break saved client connections.
    if let Some(mut f) = create_secret_file_exclusive(&path)? {
        use std::io::Write;
        let bytes = try_random::<32>()?;
        let hex = to_hex(&bytes);
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
        fsync_parent_dir(&path);
        return Ok(bytes);
    }
    // Lost the race, or a normal restart: read the winner's key through the same
    // hardened reader (symlink/perm/inode guards + exact 64-hex shape).
    let hex = read_hardened_hex_secret(&path, 64, "bunker_transport_key")?;
    decode_hex32(&hex).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bunker_transport_key is malformed; refusing to rotate identity",
        )
    })
}

/// An event pushed to connected WebSocket clients.
#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Log {
        app: String,
        action: String,
        success: bool,
        detail: Option<String>,
    },
    Approval {
        id: u64,
        app: String,
        method: String,
        kind: Option<u16>,
        preview: Option<String>,
        /// NIP-98 (kind 27235) HTTP-auth target the browser prompt must show so
        /// the operator does not approve a blind bearer credential. `None` for
        /// non-27235 requests; the `url`/`method` stay paired so they cannot
        /// desynchronize.
        http_auth: Option<HttpAuth>,
    },
}

/// The `u`/method a NIP-98 HTTP-auth signature will authenticate, surfaced in
/// the approval prompt. A field is `None` when the request omits that tag.
#[derive(Clone, Serialize)]
pub struct HttpAuth {
    pub url: Option<String>,
    pub method: Option<String>,
}
