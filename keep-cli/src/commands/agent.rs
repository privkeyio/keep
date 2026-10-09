// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::debug;
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;

use super::get_password;

/// The MCP session's scope. Bitcoin tools are opt-in: an address needs the network,
/// and signing also needs a spend limit.
fn mcp_scope(
    network: Option<&str>,
    max_amount_sats: Option<u64>,
    allow_address: Vec<String>,
) -> Result<keep_agent::scope::SessionScope> {
    use keep_agent::scope::{Operation, SessionScope};

    let mut ops = vec![Operation::SignNostrEvent, Operation::GetPublicKey];
    let Some(network) = network else {
        if max_amount_sats.is_some() || !allow_address.is_empty() {
            return Err(KeepError::InvalidInput(
                "--max-amount-sats and --allow-address need --network".into(),
            ));
        }
        return Ok(SessionScope::new(ops));
    };
    let network = super::bitcoin::parse_network(network)?;
    ops.push(Operation::GetBitcoinAddress);
    if max_amount_sats.is_some() {
        ops.push(Operation::SignPsbt);
    } else if !allow_address.is_empty() {
        return Err(KeepError::InvalidInput(
            "--allow-address needs --max-amount-sats".into(),
        ));
    }
    let mut scope = SessionScope::new(ops).with_network(network);
    if let Some(sats) = max_amount_sats {
        scope = scope.with_max_amount(sats);
    }
    if !allow_address.is_empty() {
        scope = scope.with_address_allowlist(allow_address);
    }
    scope
        .validated()
        .map_err(|e| KeepError::InvalidInput(e.to_string()))
}

pub fn cmd_agent_mcp(
    out: &Output,
    path: &Path,
    key_name: &str,
    hidden: bool,
    network: Option<&str>,
    max_amount_sats: Option<u64>,
    allow_address: Vec<String>,
) -> Result<()> {
    use keep_agent::mcp::McpServer;
    use keep_agent::session::SessionConfig;
    use std::io::{BufRead, Write};

    if hidden {
        return Err(KeepError::NotImplemented(
            "MCP server not supported for hidden volumes".into(),
        ));
    }
    let scope = mcp_scope(network, max_amount_sats, allow_address)?;

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

    // The vault stays unlocked for the server's life so every signature can be
    // recorded in its audit log before it is returned.
    let server = McpServer::with_signing(pubkey, secret, keep);
    secret.zeroize();

    let config = SessionConfig::new(scope)
        .with_duration_hours(24)
        .with_policy("cli_mcp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let (token, session_id) = rt.block_on(async {
        let (token, session_id) = server
            .create_session(config)
            .await
            .map_err(|e| KeepError::Runtime(format!("create session: {e}")))?;
        server.set_session(token.clone(), session_id.clone()).await;
        Ok::<_, KeepError>((token, session_id))
    })?;

    eprintln!("Keep MCP server started for key: {key_name}");
    eprintln!("Session ID: {session_id}");
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
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }

    Ok(())
}

/// `keep agent connect`: bridge an MCP client on stdio to the gateway.
#[cfg(target_os = "linux")]
pub fn cmd_agent_connect(token_file: &Path, socket: &Path, gateway_user: &str) -> Result<()> {
    use keep_agent::gateway::bridge::{self, Bridge, Timing, Token};
    use keep_agent::gateway::daemon;

    if let Some(var) = bridge::vault_secret_var(|v| std::env::var_os(v).is_some()) {
        return Err(KeepError::InvalidInput(format!(
            "refusing to run with {var} set: the agent can read this environment. Remove it \
             from the MCP client's configuration; the bridge needs only its token file"
        )));
    }
    let euid = daemon::euid();
    if euid == 0 {
        return Err(KeepError::InvalidInput(
            "run the bridge as the agent's user; root can hold no gateway credential".into(),
        ));
    }
    let runtime = |e: keep_agent::error::AgentError| KeepError::Runtime(e.to_string());
    // No core dump may hold the token.
    daemon::harden().map_err(runtime)?;
    let token = Token::read(token_file, euid).map_err(runtime)?;
    let gateway_uid = super::gateway::gateway_uid(gateway_user)?;
    let mut bridge = Bridge::connect(socket, gateway_uid, token, Timing::default())
        .map_err(|e| KeepError::Runtime(format!("connect to the gateway: {e}")))?;
    eprintln!(
        "keep agent connect: connected to the gateway at {}",
        socket.display()
    );
    bridge
        .serve(std::io::stdin().lock(), std::io::stdout().lock())
        .map_err(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_agent::scope::Operation;

    const MAINNET_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const TESTNET_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[test]
    fn bitcoin_tools_are_opt_in() {
        let scope = mcp_scope(None, None, vec![]).unwrap();
        assert!(scope.allows_operation(&Operation::SignNostrEvent));
        assert!(!scope.allows_operation(&Operation::GetBitcoinAddress));
        assert!(!scope.allows_operation(&Operation::SignPsbt));

        let scope = mcp_scope(Some("mainnet"), None, vec![]).unwrap();
        assert!(scope.allows_operation(&Operation::GetBitcoinAddress));
        assert!(!scope.allows_operation(&Operation::SignPsbt));
        assert_eq!(scope.network, Some(keep_bitcoin::Network::Bitcoin));

        let scope = mcp_scope(
            Some("mainnet"),
            Some(50_000),
            vec![MAINNET_ADDR.to_uppercase()],
        )
        .unwrap();
        assert!(scope.allows_operation(&Operation::SignPsbt));
        assert_eq!(scope.max_amount_sats, Some(50_000));
        assert!(scope.allows_address(MAINNET_ADDR));
        assert!(!scope.allows_operation(&Operation::Nip44Encrypt));
        assert!(!scope.allows_operation(&Operation::Nip44Decrypt));
    }

    #[test]
    fn inconsistent_flags_are_refused() {
        for (network, max, allow, expected) in [
            (None, Some(1), vec![], "--network"),
            (None, None, vec![MAINNET_ADDR.to_string()], "--network"),
            (
                Some("mainnet"),
                None,
                vec![MAINNET_ADDR.to_string()],
                "--max-amount-sats",
            ),
            (Some("main"), Some(1), vec![], "main"),
            (
                Some("mainnet"),
                Some(1),
                vec![TESTNET_ADDR.to_string()],
                TESTNET_ADDR,
            ),
        ] {
            let e = mcp_scope(network, max, allow).expect_err("must be refused");
            assert!(e.to_string().contains(expected), "{expected}: {e}");
        }
    }
}
