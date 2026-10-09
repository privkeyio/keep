// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep gateway`: run the agent gateway, and manage it over its admin socket.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use keep_agent::gateway::daemon::{self, Config, Limits, Settings, Sockets};
use keep_agent::policy::{BitcoinGrant, Grant, RequestLimits};
use keep_agent::scope::Operation;
use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::cli::GatewayCommands;
use crate::output::Output;

use super::get_password;

pub fn dispatch(out: &Output, path: &Path, command: GatewayCommands, hidden: bool) -> Result<()> {
    match command {
        GatewayCommands::Serve {
            agent_socket,
            admin_socket,
            admin_uid,
            wallet_budget_sats,
            accept_clock_jump,
        } => {
            if hidden {
                return Err(KeepError::NotImplemented(
                    "the gateway does not serve hidden volumes".into(),
                ));
            }
            let settings = Settings {
                admin_uid,
                wallet_budget_sats,
                ..Settings::default()
            };
            serve(
                out,
                Config {
                    vault: path.to_path_buf(),
                    sockets: Sockets {
                        agent: agent_socket,
                        admin: admin_socket,
                    },
                    settings,
                    limits: Limits::default(),
                    accept_clock_jump,
                },
            )
        }
        GatewayCommands::Status { admin_socket } => {
            print(&admin(&admin_socket, json!({ "op": "status" }))?)
        }
        GatewayCommands::List { admin_socket } => {
            print(&admin(&admin_socket, json!({ "op": "list" }))?)
        }
        GatewayCommands::Issue {
            admin_socket,
            name,
            uid,
            keys,
            operations,
            kinds,
            network,
            per_psbt_sats,
            window_sats,
            approval_above_sats,
            allow_addresses,
            per_minute,
            per_hour,
            per_day,
            ttl_days,
            token_out,
        } => {
            let grant = build_grant(GrantArgs {
                keys,
                operations,
                kinds,
                network,
                per_psbt_sats,
                window_sats,
                approval_above_sats,
                allow_addresses,
                limits: RequestLimits {
                    per_minute,
                    per_hour,
                    per_day,
                },
            })?;
            let ttl_secs = ttl_days
                .checked_mul(24 * 60 * 60)
                .ok_or_else(|| KeepError::InvalidInput("--ttl-days is too large".into()))?;
            // Refuse an existing token file before anything is issued.
            if let Some(file) = &token_out {
                if std::fs::symlink_metadata(file).is_ok() {
                    return Err(KeepError::InvalidInput(format!(
                        "{} already exists",
                        file.display()
                    )));
                }
            }
            let mut result = admin(
                &admin_socket,
                json!({
                    "op": "issue",
                    "name": name,
                    "uid": uid,
                    "grant": grant,
                    "ttl_secs": ttl_secs,
                }),
            )?;
            let token = Zeroizing::new(
                result
                    .as_object_mut()
                    .and_then(|o| o.remove("token"))
                    .and_then(|t| t.as_str().map(str::to_string))
                    .ok_or_else(|| KeepError::Other("the gateway returned no token".into()))?,
            );
            print(&result)?;
            match token_out {
                Some(file) => {
                    write_token(&file, &token)?;
                    out.success(&format!(
                        "Token written to {}. Give it to the agent's user; it is not shown again.",
                        file.display()
                    ));
                }
                None => {
                    out.warn("The token is shown once. Store it where only the agent's user can read it.");
                    println!("{}", token.as_str());
                }
            }
            Ok(())
        }
        GatewayCommands::Revoke { id, admin_socket } => {
            print(&admin(&admin_socket, json!({ "op": "revoke", "id": id }))?)
        }
        GatewayCommands::Delete { id, admin_socket } => {
            print(&admin(&admin_socket, json!({ "op": "delete", "id": id }))?)
        }
        GatewayCommands::Freeze {
            id,
            all,
            admin_socket,
        } => {
            let request = match (id, all) {
                (_, true) => json!({ "op": "freeze_all" }),
                (Some(id), false) => json!({ "op": "freeze", "id": id }),
                (None, false) => {
                    return Err(KeepError::InvalidInput("name a credential or --all".into()))
                }
            };
            print(&admin(&admin_socket, request)?)
        }
        GatewayCommands::Unfreeze {
            id,
            all,
            admin_socket,
        } => {
            let request = match (id, all) {
                (_, true) => json!({ "op": "unfreeze_all" }),
                (Some(id), false) => json!({ "op": "unfreeze", "id": id }),
                (None, false) => {
                    return Err(KeepError::InvalidInput("name a credential or --all".into()))
                }
            };
            print(&admin(&admin_socket, request)?)
        }
        GatewayCommands::Audit {
            limit,
            admin_socket,
        } => print(&admin(
            &admin_socket,
            json!({ "op": "audit", "limit": limit }),
        )?),
    }
}

fn serve(out: &Output, config: Config) -> Result<()> {
    if daemon::euid() == 0 {
        return Err(KeepError::InvalidInput(
            "run the gateway as its own user, never root".into(),
        ));
    }
    // Before the vault is unlocked: no core dump or same-uid debugger may
    // read the process from here on.
    daemon::harden().map_err(|e| KeepError::Runtime(e.to_string()))?;
    let stop = Arc::new(tokio::sync::Notify::new());
    if crate::GRACEFUL_STOP.set(stop.clone()).is_err() {
        return Err(KeepError::Runtime("a stop handler is already set".into()));
    }
    let mut keep = Keep::open(&config.vault)?;
    let password = get_password("Enter password")?;
    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    drop(password);
    spinner.finish();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    runtime
        .block_on(daemon::run(keep, config, async move {
            stop.notified().await;
            tracing::info!("stopping the agent gateway");
        }))
        .map_err(|e| KeepError::Runtime(e.to_string()))
}

/// Send one request to the admin socket and return its result.
fn admin(socket: &Path, request: Value) -> Result<Value> {
    let stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
        KeepError::Runtime(format!(
            "connect to the gateway's admin socket {}: {e}",
            socket.display()
        ))
    })?;
    let io = |e: std::io::Error| KeepError::Runtime(format!("admin socket: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(io)?;
    let mut writer = &stream;
    writer
        .write_all(format!("{request}\n").as_bytes())
        .map_err(io)?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(&stream).read_line(&mut line).map_err(io)?;
    if line.is_empty() {
        return Err(KeepError::Runtime(
            "the gateway closed the admin connection: run as root or the gateway's admin uid"
                .into(),
        ));
    }
    let answer: Value = serde_json::from_str(&line)
        .map_err(|e| KeepError::Runtime(format!("unexpected admin answer: {e}")))?;
    if answer["ok"] == json!(true) {
        Ok(answer["result"].clone())
    } else {
        Err(KeepError::Runtime(
            answer["error"]
                .as_str()
                .unwrap_or("the gateway refused the request")
                .to_string(),
        ))
    }
}

fn print(value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(|e| KeepError::Other(e.to_string()))?;
    println!("{text}");
    Ok(())
}

fn write_token(file: &PathBuf, token: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)
        .map_err(|e| KeepError::Runtime(format!("create {}: {e}", file.display())))?;
    f.write_all(format!("{token}\n").as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| KeepError::Runtime(format!("write {}: {e}", file.display())))
}

struct GrantArgs {
    keys: Vec<String>,
    operations: Vec<String>,
    kinds: Vec<u16>,
    network: Option<String>,
    per_psbt_sats: Option<u64>,
    window_sats: Option<u64>,
    approval_above_sats: Option<u64>,
    allow_addresses: Vec<String>,
    limits: RequestLimits,
}

/// The grant the flags describe, validated as the gateway will validate it.
fn build_grant(args: GrantArgs) -> Result<Grant> {
    let invalid = |m: String| KeepError::InvalidInput(m);
    let keys = args
        .keys
        .iter()
        .map(|k| {
            daemon::state::parse_key(k)
                .ok_or_else(|| invalid(format!("--key {k:?} is not hex or an npub")))
        })
        .collect::<Result<_>>()?;
    let operations = args
        .operations
        .iter()
        .map(|op| {
            serde_json::from_value::<Operation>(Value::String(op.clone()))
                .map_err(|_| invalid(format!("unknown operation {op:?}")))
        })
        .collect::<Result<_>>()?;
    let bitcoin = match args.network {
        Some(network) => Some(BitcoinGrant {
            network: super::bitcoin::parse_network(&network)?,
            per_psbt_sats: args.per_psbt_sats.unwrap_or(0),
            window_sats: args.window_sats.unwrap_or(0),
            approval_above_sats: args.approval_above_sats,
            address_allowlist: (!args.allow_addresses.is_empty())
                .then(|| args.allow_addresses.into_iter().collect()),
        }),
        None => {
            if args.per_psbt_sats.is_some()
                || args.window_sats.is_some()
                || args.approval_above_sats.is_some()
                || !args.allow_addresses.is_empty()
            {
                return Err(invalid("the Bitcoin limits need --network".into()));
            }
            None
        }
    };
    let grant = Grant {
        keys,
        operations,
        event_kinds: args.kinds.into_iter().collect(),
        nip44_peers: Default::default(),
        bitcoin,
        limits: args.limits,
    };
    grant.validated().map_err(|e| invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn args() -> GrantArgs {
        GrantArgs {
            keys: vec![KEY.into()],
            operations: vec!["sign_nostr_event".into()],
            kinds: vec![1],
            network: None,
            per_psbt_sats: None,
            window_sats: None,
            approval_above_sats: None,
            allow_addresses: vec![],
            limits: RequestLimits::default(),
        }
    }

    #[test]
    fn flags_build_a_validated_grant() {
        let grant = build_grant(args()).unwrap();
        assert_eq!(grant.keys.len(), 1);
        assert!(grant.operations.contains(&Operation::SignNostrEvent));
        assert_eq!(grant.event_kinds, [1].into());

        let mut btc = args();
        btc.operations = vec!["sign_psbt".into()];
        btc.network = Some("testnet".into());
        btc.per_psbt_sats = Some(1_000);
        btc.window_sats = Some(5_000);
        btc.allow_addresses = vec!["TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX".into()];
        let grant = build_grant(btc).unwrap();
        let b = grant.bitcoin.unwrap();
        assert!(b
            .address_allowlist
            .unwrap()
            .contains("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
    }

    #[test]
    fn inconsistent_flags_are_refused() {
        let refused = |f: fn(&mut GrantArgs)| {
            let mut a = args();
            f(&mut a);
            build_grant(a).unwrap_err().to_string()
        };
        assert!(refused(|a| a.keys = vec!["zz".into()]).contains("--key"));
        assert!(refused(|a| a.operations = vec!["export".into()]).contains("unknown operation"));
        assert!(refused(|a| a.kinds.clear()).contains("event kinds"));
        assert!(refused(|a| a.per_psbt_sats = Some(1)).contains("--network"));
        assert!(refused(|a| {
            a.operations = vec!["sign_psbt".into()];
            a.network = Some("mainnet".into());
            a.per_psbt_sats = Some(10);
            a.window_sats = Some(5);
        })
        .contains("per_psbt_sats"));
        assert!(refused(|a| a.limits.per_minute = 0).contains("request limits"));
    }
}
