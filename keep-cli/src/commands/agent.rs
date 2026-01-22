// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::debug;
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;

use super::get_password;

pub fn cmd_agent_mcp(out: &Output, path: &Path, key_name: &str, hidden: bool) -> Result<()> {
    use keep_agent::mcp::McpServer;
    use keep_agent::scope::SessionScope;
    use keep_agent::session::SessionConfig;
    use std::io::{BufRead, Write};

    if hidden {
        return Err(KeepError::NotImplemented(
            "MCP server not supported for hidden volumes".into(),
        ));
    }

    debug!(key_name, "starting MCP server");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let pubkey = slot.pubkey;
    let mut secret = *slot.expose_secret();

    let server = McpServer::with_signing(pubkey, secret);
    secret.zeroize();

    let config = SessionConfig::new(SessionScope::full())
        .with_duration_hours(24)
        .with_policy("cli_mcp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    let (token, session_id) = rt.block_on(async {
        let (token, session_id) = server
            .create_session(config)
            .await
            .map_err(|e| KeepError::Runtime(format!("create session: {}", e)))?;
        server.set_session(token.clone(), session_id.clone()).await;
        Ok::<_, KeepError>((token, session_id))
    })?;

    eprintln!("Keep MCP server started for key: {}", key_name);
    eprintln!("Session ID: {}", session_id);
    eprintln!("Reading JSON-RPC from stdin, writing to stdout");
    drop(token);

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = server.handle_request(&line);
        writeln!(stdout, "{}", response)?;
        stdout.flush()?;
    }

    Ok(())
}
