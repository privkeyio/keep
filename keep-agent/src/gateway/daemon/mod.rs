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

pub mod clock;
pub mod limits;
pub mod server;
pub mod state;
pub mod tools;
pub mod unlock;

#[cfg(test)]
mod tests;

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
        let open = |mode: u32, egid: u32| {
            std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(mode)).unwrap();
            super::admin_open_to_agents(&agent.join("a.sock"), &admin.join("b.sock"), egid).unwrap()
        };
        // The same group, which is not the gateway's: agents get in.
        assert!(open(0o750, gid + 1));
        assert!(open(0o710, gid + 1));
        assert!(open(0o740, gid + 1));
        // Closed to the group, or the group is the gateway's own.
        assert!(!open(0o700, gid + 1));
        assert!(!open(0o750, gid));
        if rustix::process::geteuid().is_root() {
            // A group of its own.
            std::os::unix::fs::chown(&admin, None, Some(gid + 7)).unwrap();
            assert!(!open(0o750, gid + 1));
        }
        assert!(super::admin_open_to_agents(
            &agent.join("a.sock"),
            &root.path().join("missing").join("b.sock"),
            gid
        )
        .is_err());
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

/// Whether two socket paths are in the same directory, compared by device and
/// inode so neither `.` nor a symlink can disguise it.
fn same_directory(a: &std::path::Path, b: &std::path::Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let dir = |p: &std::path::Path| {
        let parent = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                AgentError::Other(format!("{}: a socket path needs a directory", p.display()))
            })?;
        std::fs::metadata(parent)
            .map(|m| (m.dev(), m.ino()))
            .map_err(|e| AgentError::Other(format!("{}: {e}", parent.display())))
    };
    Ok(dir(a)? == dir(b)?)
}

/// Whether the admin socket's directory lets in the group of the agent
/// socket's directory: agents then reach the admin socket too, and only the
/// gateway's check of each peer keeps them out. The gateway's own group is
/// the exception, as no agent belongs to it.
fn admin_open_to_agents(
    agent: &std::path::Path,
    admin: &std::path::Path,
    egid: u32,
) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let dir = |p: &std::path::Path| {
        let parent = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                AgentError::Other(format!("{}: a socket path needs a directory", p.display()))
            })?;
        std::fs::metadata(parent)
            .map_err(|e| AgentError::Other(format!("{}: {e}", parent.display())))
    };
    let (agent, admin) = (dir(agent)?, dir(admin)?);
    Ok(admin.gid() == agent.gid() && agent.gid() != egid && admin.mode() & 0o050 != 0)
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
    } = config;
    if same_directory(&sockets.agent, &sockets.admin)? {
        return Err(AgentError::Other(
            "the admin socket needs a directory of its own, which agents cannot reach".into(),
        ));
    }
    if admin_open_to_agents(
        &sockets.agent,
        &sockets.admin,
        rustix::process::getegid().as_raw(),
    )? {
        return Err(AgentError::Other(
            "the admin socket's directory is open to the agent socket's group: give it a \
             group agents are not in, such as keep-admins"
                .into(),
        ));
    }
    let host = Host::detect(&vault)?;
    let state = State::start(
        keep,
        settings,
        host,
        Box::new(clock::Kernel),
        clock::boot_id()?,
    )?;
    let agent = server::bind(&sockets.agent, host.euid)?;
    let admin = match server::bind(&sockets.admin, host.euid) {
        Ok(admin) => admin,
        Err(e) => {
            server::remove_socket(&sockets.agent);
            return Err(e);
        }
    };
    tracing::info!(
        agent = %sockets.agent.display(),
        admin = %sockets.admin.display(),
        "agent gateway listening"
    );
    let result = server::serve(state, agent, admin, limits, shutdown).await;
    server::remove_socket(&sockets.agent);
    server::remove_socket(&sockets.admin);
    result
}
