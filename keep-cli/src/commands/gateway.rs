// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep gateway`: run the agent gateway, and manage it over its admin socket.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use keep_agent::gateway::daemon::{self, unlock, Config, Limits, Settings, Sockets};
use keep_agent::policy::{BitcoinGrant, Grant, RequestLimits};
use keep_agent::scope::Operation;
use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::cli::{AdminTarget, GatewayCommands, IssueArgs};
use crate::output::Output;

pub fn dispatch(out: &Output, path: &Path, command: GatewayCommands, hidden: bool) -> Result<()> {
    match command {
        GatewayCommands::Serve {
            agent_socket,
            admin_socket,
            admin_uid,
            wallet_budget_sats,
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
                },
            )
        }
        GatewayCommands::Status { target } => print(&admin(&target, json!({ "op": "status" }))?),
        GatewayCommands::List { target } => print(&admin(&target, json!({ "op": "list" }))?),
        GatewayCommands::Issue(args) => {
            let IssueArgs {
                target,
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
            } = *args;
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
            // The token file is created before anything is issued, so a token
            // is never issued with nowhere to go.
            let mut token_file = match &token_out {
                Some(file) => Some(create_token_file(file)?),
                None => None,
            };
            let answer = admin_answer(
                &target,
                json!({
                    "op": "issue",
                    "name": name,
                    "uid": uid,
                    "grant": grant,
                    "ttl_secs": ttl_secs,
                }),
            );
            let issued = answer.and_then(|a| match a.token {
                Some(token) => Ok((a.result, token)),
                None => Err(KeepError::Other("the gateway returned no token".into()).into()),
            });
            let (result, token) = match issued {
                Ok(issued) => issued,
                Err(failure) => {
                    if let Some(file) = &token_out {
                        let _ = std::fs::remove_file(file);
                    }
                    if !failure.maybe_done {
                        return Err(failure.error);
                    }
                    // The gateway may have issued it before the answer was lost.
                    return Err(KeepError::Runtime(format!(
                        "{}; the credential may have been issued without its token reaching \
                         you: check `keep gateway list` for one named {name:?} and revoke it",
                        failure.error
                    )));
                }
            };
            print(&result)?;
            match (token_out, token_file.take()) {
                (Some(path), Some(mut file)) => {
                    if let Err(e) = write_token(&mut file, &token) {
                        // Never leave a live credential whose token was lost.
                        let id = result["id"].as_str().unwrap_or_default().to_string();
                        let revoked = admin(&target, json!({ "op": "revoke", "id": id }));
                        let _ = std::fs::remove_file(&path);
                        return Err(KeepError::Runtime(format!(
                            "the token could not be written to {} ({e}); the credential {}",
                            path.display(),
                            if revoked.is_ok() {
                                "was revoked"
                            } else {
                                "could NOT be revoked: revoke it now"
                            }
                        )));
                    }
                    out.success(&format!(
                        "Token written to {}. Give it to the agent's user; it is not shown again.",
                        path.display()
                    ));
                }
                _ => {
                    out.warn("The token is shown once. Store it where only the agent's user can read it.");
                    println!("{}", token.as_str());
                }
            }
            Ok(())
        }
        GatewayCommands::Revoke { id, target } => {
            print(&admin(&target, json!({ "op": "revoke", "id": id }))?)
        }
        GatewayCommands::Delete { id, target } => {
            print(&admin(&target, json!({ "op": "delete", "id": id }))?)
        }
        GatewayCommands::Freeze { id, all, target } => {
            let request = match (id, all) {
                (_, true) => json!({ "op": "freeze_all" }),
                (Some(id), false) => json!({ "op": "freeze", "id": id }),
                (None, false) => {
                    return Err(KeepError::InvalidInput("name a credential or --all".into()))
                }
            };
            print(&admin(&target, request)?)
        }
        GatewayCommands::Unfreeze { id, all, target } => {
            let request = match (id, all) {
                (_, true) => json!({ "op": "unfreeze_all" }),
                (Some(id), false) => json!({ "op": "unfreeze", "id": id }),
                (None, false) => {
                    return Err(KeepError::InvalidInput("name a credential or --all".into()))
                }
            };
            print(&admin(&target, request)?)
        }
        GatewayCommands::Audit { limit, target } => {
            print(&admin(&target, json!({ "op": "audit", "limit": limit }))?)
        }
    }
}

fn serve(out: &Output, config: Config) -> Result<()> {
    // A password in the environment is visible to `systemctl show`, to
    // anything the unit's environment files reach, and to root through
    // /proc, and is too easily left there: the gateway never reads one.
    if std::env::var_os("KEEP_PASSWORD").is_some() {
        return Err(KeepError::InvalidInput(format!(
            "the gateway never reads the vault password from KEEP_PASSWORD: remove it. Under \
             systemd the password comes from the encrypted {:?} credential; otherwise it is \
             asked for on a terminal",
            unlock::PASSWORD_CREDENTIAL
        )));
    }
    if daemon::euid() == 0 {
        return Err(KeepError::InvalidInput(
            "run the gateway as its own user, never root".into(),
        ));
    }
    // Before the vault is unlocked: no core dump or same-uid debugger may
    // read the process from here on.
    daemon::harden().map_err(|e| KeepError::Runtime(e.to_string()))?;
    let mut keep = Keep::open(&config.vault)?;
    let password = vault_password()?;
    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
    drop(password);
    spinner.finish();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    // Only now does a signal stop the gateway cleanly; before, it exits at
    // once, as for any command.
    let stop = Arc::new(tokio::sync::Notify::new());
    if crate::GRACEFUL_STOP.set(stop.clone()).is_err() {
        return Err(KeepError::Runtime("a stop handler is already set".into()));
    }
    runtime
        .block_on(daemon::run(keep, config, async move {
            stop.notified().await;
            tracing::info!("stopping the agent gateway");
        }))
        .map_err(|e| KeepError::Runtime(e.to_string()))
}

/// The vault password: from the credential systemd decrypted into
/// `$CREDENTIALS_DIRECTORY`, or else asked for on a terminal.
fn vault_password() -> Result<Zeroizing<String>> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        return unlock::read_credential(
            Path::new(&dir),
            unlock::PASSWORD_CREDENTIAL,
            unlock::Reader::this_process(),
        )
        .map_err(|e| KeepError::Runtime(e.to_string()));
    }
    if !std::io::stdin().is_terminal() {
        return Err(KeepError::InvalidInput(format!(
            "no vault password: run the gateway from its systemd unit, which passes the \
             encrypted {:?} credential, or on a terminal to be asked for it",
            unlock::PASSWORD_CREDENTIAL
        )));
    }
    super::read_password("Enter password").map(Zeroizing::new)
}

/// The gateway's answer to an admin request. The token of an issued
/// credential comes beside the result, read straight into a buffer that is
/// wiped.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminAnswer {
    ok: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    token: Option<Zeroizing<String>>,
}

/// Send one request to the admin socket and return its result.
fn admin(target: &AdminTarget, request: Value) -> Result<Value> {
    admin_answer(target, request)
        .map(|a| a.result)
        .map_err(|f| f.error)
}

/// Why an admin request failed, and whether the gateway may have acted on
/// it: the request was sent, and no refusal from the gateway came back.
struct AdminFailure {
    maybe_done: bool,
    error: KeepError,
}

impl From<KeepError> for AdminFailure {
    fn from(error: KeepError) -> Self {
        Self {
            maybe_done: false,
            error,
        }
    }
}

/// The uid of the gateway's user, given by name or number. Names are looked
/// up in /etc/passwd, where a system user such as `keep-gateway` is defined.
pub(crate) fn gateway_uid(user: &str) -> Result<u32> {
    if let Ok(uid) = user.parse() {
        return Ok(uid);
    }
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| KeepError::Runtime(format!("read /etc/passwd: {e}")))?;
    passwd
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            Some((f.next()?, f.nth(1)?))
        })
        .find(|(name, _)| *name == user)
        .and_then(|(_, uid)| uid.parse().ok())
        .ok_or_else(|| {
            KeepError::InvalidInput(format!(
                "no user named {user:?} in /etc/passwd: pass --gateway-user with the \
                 gateway's user name or uid"
            ))
        })
}

/// Read one answer line straight into a buffer that is wiped, never through
/// an intermediate buffer that would be freed holding a token.
fn read_answer(mut stream: &std::os::unix::net::UnixStream) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    const MAX: usize = 64 * 1024 * 1024;
    let mut line = Zeroizing::new(Vec::with_capacity(64 * 1024));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = stream.read(&mut chunk[..])?;
        if n == 0 {
            return Ok(line);
        }
        if let Some(end) = chunk[..n].iter().position(|&b| b == b'\n') {
            extend_wiped(&mut line, &chunk[..end]);
            return Ok(line);
        }
        if line.len() + n > MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "admin answer too long",
            ));
        }
        extend_wiped(&mut line, &chunk[..n]);
    }
}

/// Append, moving to a larger buffer and wiping the old one when it is full.
fn extend_wiped(buf: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if buf.len() + bytes.len() > buf.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity((buf.len() + bytes.len()) * 2));
        grown.extend_from_slice(buf);
        *buf = grown;
    }
    buf.extend_from_slice(bytes);
}

fn admin_answer(
    target: &AdminTarget,
    request: Value,
) -> std::result::Result<AdminAnswer, AdminFailure> {
    let uid = gateway_uid(&target.gateway_user)?;
    let stream = daemon::server::connect_checked(&target.admin_socket, uid)
        .map_err(|e| KeepError::Runtime(format!("connect to the gateway's admin socket: {e}")))?;
    let io = |e: std::io::Error| KeepError::Runtime(format!("admin socket: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(io)?;
    // The gateway turns a uid it does not admit away unread.
    let closed = || {
        KeepError::Runtime(
            "the gateway closed the admin connection unread: run as root or the gateway's admin \
             uid, or retry if it is already serving as many admin connections as it allows"
                .into(),
        )
    };
    let mut writer = &stream;
    // A request not written whole was never read.
    writer
        .write_all(format!("{request}\n").as_bytes())
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => closed(),
            _ => io(e),
        })?;
    // From here the gateway may have acted on the request.
    let sent = |error: KeepError| AdminFailure {
        maybe_done: true,
        error,
    };
    let line = match read_answer(&stream) {
        Ok(line) => line,
        // Closed with the request still unread in it: never acted on.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Err(closed().into()),
        Err(e) => return Err(sent(io(e))),
    };
    if line.is_empty() {
        return Err(sent(KeepError::Runtime(
            "the gateway closed the admin connection without answering".into(),
        )));
    }
    let answer: AdminAnswer = serde_json::from_slice(&line)
        .map_err(|e| sent(KeepError::Runtime(format!("unexpected admin answer: {e}"))))?;
    if answer.ok {
        Ok(answer)
    } else {
        Err(AdminFailure {
            maybe_done: false,
            error: KeepError::Runtime(
                answer
                    .error
                    .unwrap_or_else(|| "the gateway refused the request".into()),
            ),
        })
    }
}

fn print(value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(|e| KeepError::Other(e.to_string()))?;
    println!("{text}");
    Ok(())
}

/// Create the token file, new and readable by its owner alone.
fn create_token_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| KeepError::Runtime(format!("create {}: {e}", path.display())))
}

fn write_token(file: &mut std::fs::File, token: &str) -> std::io::Result<()> {
    let mut line = Zeroizing::new(String::with_capacity(token.len() + 1));
    line.push_str(token);
    line.push('\n');
    file.write_all(line.as_bytes())?;
    file.sync_all()
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
    fn the_gateway_user_is_a_uid_or_a_name_in_passwd() {
        assert_eq!(gateway_uid("990").unwrap(), 990);
        assert_eq!(gateway_uid("root").unwrap(), 0);
        let err = gateway_uid("no-such-gateway-user").unwrap_err().to_string();
        assert!(err.contains("name or uid"), "{err}");
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
