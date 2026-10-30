// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep gateway`: the daemon that holds the unlocked vault and serves agents
//! over a Unix socket. Agents present a token with every request; the gateway
//! checks it against the peer's uid, rate limits, decides under the
//! credential's grant, signs, and records every decision before answering.
//! Requests that need an approval are refused until approvals exist.
//!
//! The owner manages credentials over a second socket, open to root and one
//! admin uid, since the vault cannot be opened by anything else while the
//! gateway holds it.

pub mod approvals;
pub mod attestation;
pub mod clock;
pub mod helper;
mod inject;
pub mod limits;
pub mod relay;
pub mod server;
pub mod state;
pub mod tools;
pub mod unlock;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod approval_tests;

#[cfg(test)]
mod relay_tests;

#[cfg(test)]
mod test_relay;

#[cfg(test)]
mod inject_tests;

#[cfg(test)]
mod ssh_tests;

#[cfg(test)]
mod dir_tests {
    #[test]
    fn the_sockets_must_be_in_different_directories_however_named() {
        let root = tempfile::tempdir().unwrap();
        let (a, b) = (root.path().join("a"), root.path().join("b"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::os::unix::fs::symlink(&a, root.path().join("link")).unwrap();
        let same =
            |x: std::path::PathBuf, y: std::path::PathBuf| super::same_directory(&x, &y).unwrap();
        assert!(same(a.join("agent.sock"), a.join("admin.sock")));
        assert!(same(a.join("agent.sock"), a.join(".").join("admin.sock")));
        assert!(same(
            a.join("agent.sock"),
            root.path().join("link").join("admin.sock")
        ));
        assert!(!same(a.join("agent.sock"), b.join("admin.sock")));
        assert!(
            super::same_directory(&a.join("x"), &root.path().join("missing").join("y")).is_err()
        );
    }

    #[test]
    fn the_admin_directory_may_not_share_a_group_with_the_agent_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let (agent, admin) = (root.path().join("agent"), root.path().join("admin"));
        std::fs::create_dir(&agent).unwrap();
        std::fs::create_dir(&admin).unwrap();
        let gid = std::fs::metadata(&agent).unwrap().gid();
        let open = |mode: u32| {
            std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(mode)).unwrap();
            super::admin_open_to_agents(&agent.join("a.sock"), &admin.join("b.sock")).unwrap()
        };
        // The same group, whichever it is: whoever reaches one reaches both.
        assert!(open(0o750));
        assert!(open(0o710));
        assert!(open(0o740));
        // Closed to the group.
        assert!(!open(0o700));
        if rustix::process::geteuid().is_root() {
            // A group of its own.
            std::os::unix::fs::chown(&admin, None, Some(gid + 7)).unwrap();
            assert!(!open(0o750));
        }
        assert!(super::admin_open_to_agents(
            &agent.join("a.sock"),
            &root.path().join("missing").join("b.sock"),
        )
        .is_err());
    }

    /// The relay socket needs a directory of its own however its path is
    /// written: agents reach the agent socket's directory, and anyone there
    /// could otherwise reach the relay socket too.
    #[tokio::test]
    async fn the_relay_socket_needs_a_directory_of_its_own_however_named() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = |name: &str, mode: u32| {
            let dir = root.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir
        };
        let (agent, admin) = (dir("agent", 0o750), dir("admin", 0o700));
        std::fs::create_dir(root.path().join("vault")).unwrap();
        for relay_socket in [
            agent.join(".").join("relay.sock"),
            admin.join("..").join("admin").join("relay.sock"),
        ] {
            let (keep, _) = super::tests::vault(&root.path().join("vault"));
            let config = super::Config {
                vault: root.path().join("vault").join("keep"),
                sockets: super::Sockets {
                    agent: agent.join("agent.sock"),
                    admin: admin.join("admin.sock"),
                },
                settings: super::Settings {
                    relay_uid: Some(4_242),
                    ..super::Settings::default()
                },
                limits: super::Limits::default(),
                approvals: super::ApprovalConfig {
                    channel: Some(super::approval_tests::channel()),
                    relays: vec!["wss://relay.example.com".into()],
                    deadline_secs: 60,
                    relay_socket: relay_socket.clone(),
                },
            };
            let Err(err) = super::run(keep, config, async {}).await else {
                panic!("{} was accepted", relay_socket.display());
            };
            assert!(
                err.to_string()
                    .contains("the relay socket needs a directory of its own"),
                "{err}"
            );
        }
    }

    #[test]
    fn readiness_reaches_a_path_or_an_abstract_notification_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("notify");
        let by_path = UnixDatagram::bind(&path).unwrap();
        super::notify(path.as_os_str(), b"READY=1").unwrap();
        let mut buf = [0u8; 64];
        let n = by_path.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");

        let name = format!("keep-notify-test-{}", std::process::id());
        let abstract_addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let by_name = UnixDatagram::bind_addr(&abstract_addr).unwrap();
        super::notify(std::ffi::OsStr::new(&format!("@{name}")), b"READY=1").unwrap();
        let n = by_name.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");

        for bad in ["", "relative", "vsock:1:2"] {
            assert!(
                super::notify(std::ffi::OsStr::new(bad), b"READY=1").is_err(),
                "{bad}"
            );
        }
        assert!(super::notify(root.path().join("missing").as_os_str(), b"READY=1").is_err());
    }
}

use std::path::PathBuf;

use keep_core::Keep;

pub use server::{Limits, Sockets};
pub use state::{AdminRequest, Host, Settings, State};

use crate::error::{AgentError, Result};

/// Everything a gateway runs with.
#[derive(Debug, Clone)]
pub struct Config {
    /// The vault directory.
    pub vault: PathBuf,
    pub sockets: Sockets,
    pub settings: Settings,
    pub limits: Limits,
    pub approvals: ApprovalConfig,
}

/// Approvals over Nostr: the channel key, read from its own credential
/// (never from the vault), the relays, the deadline, and the relay helper's
/// socket. The helper's user is [`Settings::relay_uid`].
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    pub channel: Option<nostr_sdk::prelude::Keys>,
    pub relays: Vec<String>,
    pub deadline_secs: u64,
    pub relay_socket: PathBuf,
}

/// The name of the credential holding the channel key.
pub const CHANNEL_KEY_CREDENTIAL: &str = "channel-key";

/// The channel key from the text of its credential: 64 hex digits.
pub fn parse_channel_key(text: &str) -> Result<nostr_sdk::prelude::Keys> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    if text.len() != 64 || hex::decode_to_slice(text, secret.as_mut()).is_err() {
        return Err(AgentError::Other(
            "the channel-key credential holds 64 hex digits".into(),
        ));
    }
    nostr_sdk::prelude::SecretKey::from_slice(secret.as_ref())
        .map(nostr_sdk::prelude::Keys::new)
        .map_err(|_| AgentError::Other("the channel-key credential is not a key".into()))
}

/// This process's effective uid.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Keep this process's memory out of core dumps and away from same-uid
/// debuggers. Call before the vault is unlocked.
pub fn harden() -> Result<()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| AgentError::Other(format!("PR_SET_DUMPABLE: {e}")))
}

/// The metadata of a socket path's directory.
fn socket_directory(socket: &std::path::Path) -> Result<std::fs::Metadata> {
    let parent = socket
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| {
            AgentError::Other(format!(
                "{}: a socket path needs a directory",
                socket.display()
            ))
        })?;
    std::fs::metadata(parent).map_err(|e| AgentError::Other(format!("{}: {e}", parent.display())))
}

/// Whether two socket paths are in the same directory, compared by device and
/// inode so neither `.` nor a symlink can disguise it.
fn same_directory(a: &std::path::Path, b: &std::path::Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (a, b) = (socket_directory(a)?, socket_directory(b)?);
    Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
}

/// Whether the admin socket's directory lets in the group of the agent
/// socket's directory: agents reach the agent socket through that group, so
/// they would reach the admin socket too, and only the gateway's check of
/// each peer would keep them out.
fn admin_open_to_agents(agent: &std::path::Path, admin: &std::path::Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (agent, admin) = (socket_directory(agent)?, socket_directory(admin)?);
    Ok(admin.gid() == agent.gid() && admin.mode() & 0o050 != 0)
}

/// Tell systemd the gateway is ready, when a unit of `Type=notify` started
/// it: the vault is unlocked and both sockets listen.
fn notify_ready() -> Result<()> {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(socket) => notify(&socket, b"READY=1"),
        None => Ok(()),
    }
}

/// Send `message` to the systemd notification socket `socket`: a path, or an
/// abstract name written with a leading `@`.
fn notify(socket: &std::ffi::OsStr, message: &[u8]) -> Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let fail = |e: std::io::Error| AgentError::Other(format!("NOTIFY_SOCKET: {e}"));
    let addr = match socket.as_bytes() {
        [b'@', name @ ..] => SocketAddr::from_abstract_name(name),
        path @ [b'/', ..] => SocketAddr::from_pathname(std::ffi::OsStr::from_bytes(path)),
        _ => {
            return Err(AgentError::Other(
                "NOTIFY_SOCKET is neither a path nor an abstract socket name".into(),
            ))
        }
    }
    .map_err(fail)?;
    let sent = UnixDatagram::unbound()
        .and_then(|s| s.send_to_addr(message, &addr))
        .map_err(fail)?;
    if sent != message.len() {
        return Err(AgentError::Other("NOTIFY_SOCKET: short send".into()));
    }
    Ok(())
}

/// Serve `keep` until `shutdown` resolves.
pub async fn run(
    keep: Keep,
    config: Config,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let Config {
        vault,
        sockets,
        settings,
        limits,
        approvals,
    } = config;
    if same_directory(&sockets.agent, &sockets.admin)? {
        return Err(AgentError::Other(
            "the admin socket needs a directory of its own, which agents cannot reach".into(),
        ));
    }
    if admin_open_to_agents(&sockets.agent, &sockets.admin)? {
        return Err(AgentError::Other(
            "the admin socket's directory is open to the agent socket's group: give it a \
             group agents are not in, such as keep-admins"
                .into(),
        ));
    }
    let host = Host::detect(&vault)?;
    let relay_uid = settings.relay_uid;
    let mut state = State::start(
        keep,
        settings,
        host,
        Box::new(clock::Kernel),
        clock::boot_id()?,
    )?;
    let with_channel = approvals.channel.is_some();
    state.configure_approvals(approvals.channel, approvals.relays, approvals.deadline_secs)?;
    let relay_at = match (with_channel, relay_uid) {
        (false, _) => None,
        (true, Some(uid)) => {
            let path = approvals.relay_socket;
            if same_directory(&path, &sockets.agent)? || same_directory(&path, &sockets.admin)? {
                return Err(AgentError::Other(
                    "the relay socket needs a directory of its own".into(),
                ));
            }
            Some((path, uid))
        }
        (true, None) => {
            return Err(AgentError::Other(
                "approvals need the relay helper's user".into(),
            ))
        }
    };
    let agent = server::bind(&sockets.agent, host.euid)?;
    let admin = match server::bind(&sockets.admin, host.euid) {
        Ok(admin) => admin,
        Err(e) => {
            server::remove_socket(&sockets.agent);
            return Err(e);
        }
    };
    let relay = match &relay_at {
        None => None,
        Some((path, uid)) => match server::bind(path, host.euid) {
            Ok(listener) => Some((listener, *uid)),
            Err(e) => {
                server::remove_socket(&sockets.agent);
                server::remove_socket(&sockets.admin);
                return Err(e);
            }
        },
    };
    tracing::info!(
        agent = %sockets.agent.display(),
        admin = %sockets.admin.display(),
        "agent gateway listening"
    );
    #[cfg(keep_e2e_roots)]
    tracing::warn!(
        app_signer = attestation::E2E_APP_SIGNER.unwrap_or("none"),
        "an end to end test build, never to be deployed: it trusts a test attestation root, \
         a test inject CA and the test app signer named here"
    );
    let remove_all = || {
        server::remove_socket(&sockets.agent);
        server::remove_socket(&sockets.admin);
        if let Some((path, _)) = &relay_at {
            server::remove_socket(path);
        }
    };
    if let Err(e) = notify_ready() {
        remove_all();
        return Err(e);
    }
    let result = server::serve(state, agent, admin, relay, limits, shutdown).await;
    remove_all();
    result
}
