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

#[cfg(test)]
mod tests;

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
    /// The owner confirmed a wall clock far ahead of what the vault last saw.
    pub accept_clock_jump: bool,
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
        accept_clock_jump,
    } = config;
    if sockets.agent.parent() == sockets.admin.parent() {
        return Err(AgentError::Other(
            "the admin socket needs a directory of its own, which agents cannot reach".into(),
        ));
    }
    let host = Host::detect(&vault)?;
    let state = State::start(
        keep,
        settings,
        host,
        Box::new(clock::Kernel),
        clock::boot_id()?,
        clock::wall_clock()?,
        accept_clock_jump,
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
