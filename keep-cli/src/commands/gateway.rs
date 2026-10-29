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

use crate::cli::{AdminTarget, ApproverCommands, ChannelKeyCommands, GatewayCommands, IssueArgs};
use crate::output::Output;

pub fn dispatch(out: &Output, path: &Path, command: GatewayCommands, hidden: bool) -> Result<()> {
    match command {
        GatewayCommands::Serve {
            agent_socket,
            admin_socket,
            admin_uid,
            wallet_budget_sats,
            approval_relays,
            approval_deadline,
            relay_socket,
            relay_user,
            inject_socket,
        } => {
            if hidden {
                return Err(KeepError::NotImplemented(
                    "the gateway does not serve hidden volumes".into(),
                ));
            }
            let relay_uid = if approval_relays.is_empty() {
                None
            } else {
                Some(gateway_uid(&relay_user)?)
            };
            let settings = Settings {
                admin_uid,
                relay_uid,
                wallet_budget_sats,
                inject: inject_socket
                    .map(|socket| daemon::state::InjectSettings { socket, owner: 0 }),
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
                    approvals: daemon::ApprovalConfig {
                        channel: None,
                        relays: approval_relays,
                        deadline_secs: approval_deadline,
                        relay_socket,
                    },
                },
            )
        }
        GatewayCommands::Relay { .. }
        | GatewayCommands::ChannelKey { .. }
        | GatewayCommands::InjectWorker {} => dispatch_without_vault(command),
        GatewayCommands::Approver { command } => approver(out, path, command),
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
                secrets_file,
            } = *args;
            let secrets = match &secrets_file {
                Some(file) => read_secrets_file(file)?,
                None => Vec::new(),
            };
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
                secrets,
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

/// The commands that need no vault: the relay helper, and making a channel
/// key.
pub fn dispatch_without_vault(command: GatewayCommands) -> Result<()> {
    match command {
        GatewayCommands::Relay {
            relay_socket,
            gateway_user,
        } => relay(&relay_socket, &gateway_user),
        GatewayCommands::ChannelKey {
            command: ChannelKeyCommands::New,
        } => new_channel_key(),
        GatewayCommands::InjectWorker {} => inject_worker(),
        _ => Err(KeepError::Other("this command needs the vault".into())),
    }
}

/// The channel key from the credential systemd decrypted, if it loaded one.
fn channel_key() -> Result<Option<nostr_sdk::prelude::Keys>> {
    let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(None);
    };
    let dir = Path::new(&dir);
    if std::fs::symlink_metadata(dir.join(daemon::CHANNEL_KEY_CREDENTIAL)).is_err() {
        return Ok(None);
    }
    let text = unlock::read_credential(
        dir,
        daemon::CHANNEL_KEY_CREDENTIAL,
        unlock::Reader::this_process(),
    )
    .map_err(|e| KeepError::Runtime(e.to_string()))?;
    daemon::parse_channel_key(&text)
        .map(Some)
        .map_err(|e| KeepError::Runtime(e.to_string()))
}

/// `keep gateway channel-key new`: the secret goes only to a pipe, into
/// `systemd-creds encrypt`, never to a terminal or a file.
fn new_channel_key() -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let piped = std::fs::metadata("/proc/self/fd/1").is_ok_and(|m| m.file_type().is_fifo());
    if !piped {
        return Err(KeepError::InvalidInput(
            "the channel key is written only to a pipe: run `keep gateway channel-key new | \
             systemd-creds encrypt --name=channel-key --with-key=host+tpm2 --tpm2-pcrs=7 - \
             /etc/keep/gateway/channel-key.cred`"
                .into(),
        ));
    }
    let keys = nostr_sdk::prelude::Keys::generate();
    let mut line = Zeroizing::new(keys.secret_key().to_secret_hex());
    line.push('\n');
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| KeepError::Runtime(format!("write the channel key: {e}")))?;
    drop(line);
    use nostr_sdk::prelude::ToBech32;
    let npub = keys
        .public_key()
        .to_bech32()
        .map_err(|e| KeepError::Other(e.to_string()))?;
    eprintln!("channel key {npub} ({})", keys.public_key().to_hex());
    Ok(())
}

/// `keep gateway relay`: run the relay helper until stopped.
fn relay(socket: &Path, gateway_user: &str) -> Result<()> {
    let uid = gateway_uid(gateway_user)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    let stop = Arc::new(tokio::sync::Notify::new());
    if crate::GRACEFUL_STOP.set(stop.clone()).is_err() {
        return Err(KeepError::Runtime("a stop handler is already set".into()));
    }
    runtime
        .block_on(daemon::helper::run_helper(socket, uid, async move {
            stop.notified().await;
            tracing::info!("stopping the relay helper");
        }))
        .map_err(|e| KeepError::Runtime(e.to_string()))
}

fn inject_worker() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    let done = runtime.block_on(keep_agent::inject::worker::run());
    // Standard input is read on a blocking thread the runtime would wait on;
    // the answer is written, so exit without waiting.
    std::process::exit(match done {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, "inject worker");
            1
        }
    })
}

fn approver(out: &Output, path: &Path, command: ApproverCommands) -> Result<()> {
    match command {
        ApproverCommands::List { target } => {
            print(&admin(&target, json!({ "op": "approver_list" }))?)
        }
        ApproverCommands::Remove { transport, target } => print(&admin(
            &target,
            json!({ "op": "approver_remove", "transport": transport }),
        )?),
        ApproverCommands::Reset { offline, target } => {
            if !offline {
                if daemon::euid() != 0 {
                    return Err(KeepError::InvalidInput(
                        "only root may reset the approver devices".into(),
                    ));
                }
                return print(&admin(&target, json!({ "op": "approver_reset" }))?);
            }
            // The gateway is stopped (a new host, a cleared TPM): reset the
            // vault directly, recorded in its audit log. The vault password is
            // the authority here, and the vault's own user runs it, so no file
            // in the vault comes to belong to anyone else.
            use std::os::unix::fs::MetadataExt;
            let owner = std::fs::metadata(path)
                .map_err(|e| KeepError::Runtime(format!("{}: {e}", path.display())))?
                .uid();
            if daemon::euid() != owner {
                return Err(KeepError::InvalidInput(format!(
                    "run the offline reset as the vault's owner, uid {owner} (for the gateway, \
                     `sudo -u keep-gateway`)"
                )));
            }
            let mut keep = Keep::open(path)?;
            let password = vault_password()?;
            keep.unlock(&password)?;
            drop(password);
            let removed = daemon::state::reset_store(&mut keep)
                .map_err(|e| KeepError::Runtime(e.to_string()))?;
            keep.lock();
            out.success(&format!("Removed {removed} approver device(s)"));
            Ok(())
        }
        ApproverCommands::Pair {
            label,
            attestation_status,
            target,
        } => pair(out, &label, attestation_status.as_deref(), &target),
    }
}

/// Pair a phone over one admin connection: show the code, wait for the
/// phone, show its fingerprint, ask the operator, and wait for the outcome.
/// The gateway checks the phone's attestation but cannot reach Google, so
/// the certificates it names are checked here against Google's status list,
/// read before the session opens.
fn pair(out: &Output, label: &str, status: Option<&Path>, target: &AdminTarget) -> Result<()> {
    // Checked before the gateway opens a session nobody could confirm.
    need_terminal()?;
    let unusable = attestation_status(status)?;
    let mut session = AdminSession::open(target, PAIR_WAIT)?;
    session
        .write(&json!({ "op": "approver_pair", "label": label }))
        .map_err(|f| f.error)?;
    let uri = session.pairing_code()?;
    show_qr(&uri);
    println!("{}", uri.as_str());
    out.info("Scan the code with the phone. It is valid for ten minutes and one phone.");
    let shown = session.next()?;
    let fingerprint = shown.result["fingerprint"].as_str().unwrap_or_default();
    let phone_label = shown.result["phone_label"].as_str().unwrap_or_default();
    if let Err(why) = check_attestation(&shown.result["attestation"], &unusable) {
        session.ask(&json!({ "op": "approver_reject" }))?;
        return Err(KeepError::InvalidInput(format!(
            "the phone was refused: {why}"
        )));
    }
    let attestation = &shown.result["attestation"];
    out.info(&format!(
        "The phone's approver key is attested: {}, {}.",
        if attestation["strongbox"] == true {
            "kept in StrongBox"
        } else {
            "kept in the TEE"
        },
        if attestation["grapheneos"] == true {
            "on GrapheneOS"
        } else {
            "on its maker's verified OS"
        }
    ));
    println!(
        "Phone \"{}\" shows fingerprint:  {fingerprint}",
        phone_label.escape_debug()
    );
    let confirmed = confirm("Does the phone show the same fingerprint? [y/N] ")?;
    let op = if confirmed {
        "approver_confirm"
    } else {
        "approver_reject"
    };
    let mut answer = session.ask(&json!({ "op": op }))?;
    if answer.pending.is_some() {
        out.info("Waiting for an approver device to approve adding this one...");
        answer = session.next()?;
    }
    if !confirmed {
        return Err(KeepError::InvalidInput(
            "the fingerprints did not match: the phone was refused".into(),
        ));
    }
    print(&answer.result)
}

/// The serial numbers Google's attestation status list marks revoked or
/// suspended, from `file` or fetched.
fn attestation_status(file: Option<&Path>) -> Result<std::collections::HashSet<String>> {
    use keep_agent::gateway::daemon::attestation::{fetch_status, unusable_serials, STATUS_URL};
    let list = match file {
        Some(path) => std::fs::read(path).map_err(|e| {
            KeepError::InvalidInput(format!("reading {}: {e}", path.display()))
        })?,
        None => fetch_status().map_err(|e| {
            KeepError::Runtime(format!(
                "{e}; on a host that cannot reach Google, save {STATUS_URL} elsewhere and pass it with --attestation-status"
            ))
        })?,
    };
    unusable_serials(&list).map_err(KeepError::InvalidInput)
}

/// Refuse a phone whose attestation names a revoked or suspended
/// certificate, or that the gateway reported no attestation for.
fn check_attestation(
    attestation: &Value,
    unusable: &std::collections::HashSet<String>,
) -> std::result::Result<(), String> {
    let serials = attestation["serials"]
        .as_array()
        .filter(|s| !s.is_empty())
        .ok_or("the gateway reported no attestation for it")?;
    for serial in serials {
        let serial = serial
            .as_str()
            .ok_or("the gateway reported a malformed attestation")?;
        if unusable.contains(serial) {
            return Err(format!(
                "its attestation certificate {serial} is revoked or suspended by Google"
            ));
        }
    }
    Ok(())
}

/// How long `approver pair` waits on the phone and the operator: the
/// pairing session, and the longest deadline an approver may be given.
const PAIR_WAIT: Duration = Duration::from_secs(
    daemon::approvals::PAIRING_SECS + *keep_approval::binding::DEADLINE_SECS.end() + 30,
);

fn need_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(KeepError::InvalidInput(
            "the fingerprint must be confirmed on a terminal".into(),
        ));
    }
    Ok(())
}

/// Ask `prompt` on the terminal [`pair`] checked for.
fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{prompt}");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Show `text` as a QR code on the terminal.
fn show_qr(text: &str) {
    match qrcode::QrCode::new(text.as_bytes()) {
        Ok(code) => {
            let image = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("{image}");
        }
        Err(e) => eprintln!("the pairing code cannot be shown as a QR code: {e}"),
    }
}

fn serve(out: &Output, mut config: Config) -> Result<()> {
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
    // The channel key is a secret like the password: read only now, under
    // the same checks.
    config.approvals.channel = channel_key()?;
    if !config.approvals.relays.is_empty() && config.approvals.channel.is_none() {
        return Err(KeepError::InvalidInput(format!(
            "approvals need the {:?} credential: generate it with `keep gateway channel-key \
             new` and load it in the unit",
            daemon::CHANNEL_KEY_CREDENTIAL
        )));
    }
    if config.approvals.relays.is_empty() && config.approvals.channel.is_some() {
        return Err(KeepError::InvalidInput(
            "approvals need at least one relay: pass --approval-relay".into(),
        ));
    }
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
    /// The change waits for an approver device: the request id, with the
    /// outcome on the next line.
    #[serde(default)]
    pending: Option<String>,
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
/// The next line from `stream`, keeping what was read past it in `rest`
/// for the next call; at the end of the stream, whatever is left.
fn read_answer(
    mut stream: &std::os::unix::net::UnixStream,
    rest: &mut Zeroizing<Vec<u8>>,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    const MAX: usize = 64 * 1024 * 1024;
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        if let Some(end) = rest.iter().position(|&b| b == b'\n') {
            let mut line = Zeroizing::new(Vec::with_capacity(end));
            line.extend_from_slice(&rest[..end]);
            let mut left = Zeroizing::new(Vec::with_capacity(rest.len() - end - 1));
            left.extend_from_slice(&rest[end + 1..]);
            *rest = left;
            return Ok(line);
        }
        let n = stream.read(&mut chunk[..])?;
        if n == 0 {
            return Ok(std::mem::take(rest));
        }
        if rest.len() + n > MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "admin answer too long",
            ));
        }
        extend_wiped(rest, &chunk[..n]);
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

/// How long an admin command waits for an answer: the longest deadline the
/// gateway may give an approver, whatever it was started with, and a margin.
const ADMIN_WAIT: Duration = Duration::from_secs(*keep_approval::binding::DEADLINE_SECS.end() + 30);

/// One connection to the admin socket, for a request and the answers that
/// follow it.
struct AdminSession {
    stream: std::os::unix::net::UnixStream,
    /// Whether a request has been written, so the gateway may have acted.
    sent: bool,
    /// What was read past the last answer line.
    rest: Zeroizing<Vec<u8>>,
}

fn io_error(e: std::io::Error) -> KeepError {
    KeepError::Runtime(format!("admin socket: {e}"))
}

/// The gateway turns a uid it does not admit away unread.
fn closed_unread() -> KeepError {
    KeepError::Runtime(
        "the gateway closed the admin connection unread: run as root or the gateway's admin \
         uid, or retry if it is already serving as many admin connections as it allows"
            .into(),
    )
}

impl AdminSession {
    fn open(target: &AdminTarget, wait: Duration) -> Result<Self> {
        let uid = gateway_uid(&target.gateway_user)?;
        let stream = daemon::server::connect_checked(&target.admin_socket, uid).map_err(|e| {
            KeepError::Runtime(format!("connect to the gateway's admin socket: {e}"))
        })?;
        stream.set_read_timeout(Some(wait)).map_err(io_error)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(io_error)?;
        Ok(Self {
            stream,
            sent: false,
            rest: Zeroizing::new(Vec::new()),
        })
    }

    fn write(&mut self, request: &Value) -> std::result::Result<(), AdminFailure> {
        let mut writer = &self.stream;
        // A request not written whole was never read.
        writer
            .write_all(format!("{request}\n").as_bytes())
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                    AdminFailure::from(closed_unread())
                }
                _ => AdminFailure {
                    maybe_done: self.sent,
                    error: io_error(e),
                },
            })?;
        self.sent = true;
        Ok(())
    }

    /// The next answer line.
    fn read(&mut self) -> std::result::Result<AdminAnswer, AdminFailure> {
        let sent = |error: KeepError| AdminFailure {
            maybe_done: true,
            error,
        };
        let line = self.read_line()?;
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

    /// The next answer line, in a buffer that is wiped.
    fn read_line(&mut self) -> std::result::Result<Zeroizing<Vec<u8>>, AdminFailure> {
        let line = match read_answer(&self.stream, &mut self.rest) {
            Ok(line) => line,
            // Closed with the request still unread in it: never acted on.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err(closed_unread().into())
            }
            Err(e) => {
                return Err(AdminFailure {
                    maybe_done: true,
                    error: io_error(e),
                })
            }
        };
        if line.is_empty() {
            return Err(AdminFailure {
                maybe_done: true,
                error: KeepError::Runtime(
                    "the gateway closed the admin connection without answering".into(),
                ),
            });
        }
        Ok(line)
    }

    /// The answer to `approver_pair`: the pairing code, which carries the
    /// session's secret, read straight from the wiped line into a string
    /// that is wiped, never into a JSON value.
    fn pairing_code(&mut self) -> Result<Zeroizing<String>> {
        #[derive(serde::Deserialize)]
        struct Code {
            uri: Zeroizing<String>,
        }
        #[derive(serde::Deserialize)]
        struct Answer {
            ok: bool,
            #[serde(default)]
            result: Option<Code>,
            #[serde(default)]
            error: Option<String>,
        }
        let line = self.read_line().map_err(|f| f.error)?;
        let answer: Answer = serde_json::from_slice(&line)
            .map_err(|e| KeepError::Runtime(format!("unexpected admin answer: {e}")))?;
        match answer {
            Answer {
                ok: true,
                result: Some(code),
                ..
            } => Ok(code.uri),
            Answer { ok: true, .. } => Err(KeepError::Runtime(
                "the gateway sent no pairing code".into(),
            )),
            Answer { error, .. } => {
                Err(KeepError::Runtime(error.unwrap_or_else(|| {
                    "the gateway refused the request".into()
                })))
            }
        }
    }

    /// Send `request` and return its answer; a change that waits for an
    /// approver device returns the outcome once it comes.
    fn request(&mut self, request: &Value) -> std::result::Result<AdminAnswer, AdminFailure> {
        self.write(request)?;
        let answer = self.read()?;
        if answer.pending.is_some() {
            eprintln!("Waiting for an approver device to approve...");
            return self.read();
        }
        Ok(answer)
    }

    /// [`Self::request`] without its failure's detail.
    fn ask(&mut self, request: &Value) -> Result<AdminAnswer> {
        self.write(request).map_err(|f| f.error)?;
        self.read().map_err(|f| f.error)
    }

    /// The next answer, as [`Self::ask`] returns it.
    fn next(&mut self) -> Result<AdminAnswer> {
        self.read().map_err(|f| f.error)
    }
}

fn admin_answer(
    target: &AdminTarget,
    request: Value,
) -> std::result::Result<AdminAnswer, AdminFailure> {
    let mut session = AdminSession::open(target, ADMIN_WAIT)?;
    session.request(&request)
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
    secrets: Vec<Value>,
}

/// The secret entries in `file`, a JSON array. They hold no secret values,
/// only ids or names and where each may be sent.
fn read_secrets_file(file: &std::path::Path) -> Result<Vec<Value>> {
    let invalid = |m: String| KeepError::InvalidInput(m);
    let text = std::fs::read_to_string(file)
        .map_err(|e| invalid(format!("--secrets-file {}: {e}", file.display())))?;
    match serde_json::from_str(&text) {
        Ok(Value::Array(entries)) => Ok(entries),
        _ => Err(invalid(format!(
            "--secrets-file {} must hold a JSON array of secret entries",
            file.display()
        ))),
    }
}

/// The grant the flags and secrets describe, as sent to the gateway. Without
/// secrets it is validated here as the gateway will validate it; secrets go
/// as the owner wrote them, since only the gateway can resolve their names
/// and check them in the vault.
fn build_grant(args: GrantArgs) -> Result<Value> {
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
        secrets: Vec::new(),
        keys,
        operations,
        event_kinds: args.kinds.into_iter().collect(),
        nip44_peers: Default::default(),
        bitcoin,
        limits: args.limits,
    };
    let grant = if args.secrets.is_empty() {
        grant
            .validated(&keep_agent::policy::ReservedKeys::new())
            .map_err(|e| invalid(e.to_string()))?
    } else {
        grant
    };
    let mut value = serde_json::to_value(&grant).map_err(|e| invalid(e.to_string()))?;
    if !args.secrets.is_empty() {
        value["secrets"] = Value::Array(args.secrets);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_is_refused_for_a_revoked_or_missing_attestation() {
        let unusable = ["2c8c".to_string()].into_iter().collect();
        let attested = |serials: Value| json!({ "serials": serials, "strongbox": false });
        assert!(check_attestation(&attested(json!(["3", "11"])), &unusable).is_ok());
        let err = check_attestation(&attested(json!(["3", "2c8c"])), &unusable).unwrap_err();
        assert!(err.contains("2c8c is revoked"), "{err}");
        for bad in [Value::Null, attested(json!([])), attested(json!([3]))] {
            assert!(check_attestation(&bad, &unusable).is_err(), "{bad}");
        }
    }

    /// Answers that arrive in one read are each taken in turn.
    #[test]
    fn answers_read_together_are_each_kept() {
        let (stream, mut gateway) = std::os::unix::net::UnixStream::pair().unwrap();
        gateway
            .write_all(b"{\"ok\":true,\"pending\":true}\n{\"ok\":true,\"result\":1}\n")
            .unwrap();
        drop(gateway);
        let mut session = AdminSession {
            stream,
            sent: true,
            rest: Zeroizing::new(Vec::new()),
        };
        assert_eq!(
            &session.read_line().ok().unwrap()[..],
            b"{\"ok\":true,\"pending\":true}"
        );
        assert_eq!(
            &session.read_line().ok().unwrap()[..],
            b"{\"ok\":true,\"result\":1}"
        );
        assert!(session.read_line().is_err());
    }

    /// The pairing code is read from the answer line as it is, and a
    /// refusal or a missing code is an error.
    #[test]
    fn the_pairing_code_is_read_from_its_answer() {
        let code = |line: &str| {
            let (stream, mut gateway) = std::os::unix::net::UnixStream::pair().unwrap();
            gateway.write_all(line.as_bytes()).unwrap();
            AdminSession {
                stream,
                sent: true,
                rest: Zeroizing::new(Vec::new()),
            }
            .pairing_code()
        };
        let uri =
            code("{\"ok\":true,\"result\":{\"expires_in\":600,\"uri\":\"keep-approval:x\"}}\n");
        assert_eq!(uri.unwrap().as_str(), "keep-approval:x");
        let err = code("{\"ok\":false,\"error\":\"approvals are not set up\"}\n").unwrap_err();
        assert!(err.to_string().contains("not set up"), "{err}");
        assert!(code("{\"ok\":true,\"result\":{}}\n").is_err());
    }

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
            secrets: vec![],
        }
    }

    fn checked(args: GrantArgs) -> Result<Grant> {
        build_grant(args).map(|v| serde_json::from_value(v).unwrap())
    }

    #[test]
    fn flags_build_a_validated_grant() {
        let grant = checked(args()).unwrap();
        assert_eq!(grant.keys.len(), 1);
        assert!(grant.operations.contains(&Operation::SignNostrEvent));
        assert_eq!(grant.event_kinds, [1].into());

        let mut btc = args();
        btc.operations = vec!["sign_psbt".into()];
        btc.network = Some("testnet".into());
        btc.per_psbt_sats = Some(1_000);
        btc.window_sats = Some(5_000);
        btc.allow_addresses = vec!["TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX".into()];
        let grant = checked(btc).unwrap();
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
        assert!(refused(|a| a.keys.clear()).contains("keys"));
    }

    fn rule(prefix: &str) -> Value {
        json!({
            "host": "api.example.com", "port": 443, "methods": ["GET"],
            "path_prefix": prefix, "header": "authorization", "format": "Bearer {}"
        })
    }

    #[test]
    fn secrets_are_sent_as_written_for_the_gateway_to_resolve() {
        let with = |secrets: Vec<Value>| GrantArgs {
            keys: vec![],
            operations: vec!["http_request".into()],
            kinds: vec![],
            secrets,
            ..args()
        };
        let named = json!({ "secret": { "name": "deploy token" }, "http": [rule("/v1")] });
        let by_id = json!({ "secret": "ab".repeat(32), "http": [rule("/v2")] });
        let sent = build_grant(with(vec![named.clone(), by_id.clone()])).unwrap();
        assert_eq!(sent["secrets"], json!([named, by_id]));
        assert_eq!(sent["keys"], json!([]));
        let refused = build_grant(with(vec![])).unwrap_err().to_string();
        assert!(refused.contains("http_request"), "{refused}");
    }

    #[test]
    fn a_secrets_file_holds_a_json_array() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.json");
        std::fs::write(&file, r#"[{"secret":{"name":"t"},"http":[]}]"#).unwrap();
        assert_eq!(read_secrets_file(&file).unwrap().len(), 1);
        std::fs::write(&file, r#"{"secret":"x"}"#).unwrap();
        assert!(read_secrets_file(&file).is_err());
        assert!(read_secrets_file(&dir.path().join("missing")).is_err());
    }
}
