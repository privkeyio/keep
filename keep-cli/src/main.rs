// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![deny(unsafe_code)]

mod cli;
mod commands;
mod config;
mod output;
mod panic;
#[cfg(windows)]
mod panic_windows;
mod signer;
mod tui;
#[cfg(feature = "warden")]
mod warden;

use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use tracing::debug;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use keep_core::crypto::disable_mlock;
use keep_core::error::Result;

use crate::cli::*;
use crate::config::Config;
use crate::output::Output;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("req-{id:08x}")
}

fn init_logging() {
    let use_json = std::env::var("KEEP_LOG_JSON").is_ok();
    let filter = EnvFilter::from_default_env();

    if use_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::CLOSE)
            .with_current_span(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .without_time()
            .with_span_events(FmtSpan::CLOSE)
            .init();
    }
}

fn main() {
    init_logging();
    panic::install();
    keep_frost_net::install_default_crypto_provider();

    ctrlc::set_handler(|| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        std::process::exit(130);
    })
    .ok();

    let out = Output::new();

    if let Err(e) = run(&out) {
        out.error(&e.to_string());
        std::process::exit(1);
    }
}

#[tracing::instrument(skip(out), fields(request_id = %next_request_id()))]
fn run(out: &Output) -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load()?;

    if cli.no_mlock {
        disable_mlock();
    }

    let path = match cli.path {
        Some(p) => p,
        None => cfg.vault_path()?,
    };
    let hidden = cli.hidden;

    debug!(path = %path.display(), hidden, "starting command");

    match cli.command {
        Commands::Init { size } => commands::vault::cmd_init(out, &path, hidden, size),
        Commands::Generate { name } => commands::vault::cmd_generate(out, &path, &name, hidden),
        Commands::Import { name } => commands::vault::cmd_import(out, &path, &name, hidden),
        Commands::List => commands::vault::cmd_list(out, &path, hidden),
        Commands::Export { name } => commands::vault::cmd_export(out, &path, &name, hidden),
        Commands::Delete { name } => commands::vault::cmd_delete(out, &path, &name, hidden),
        Commands::RotatePassword => commands::vault::cmd_rotate_password(out, &path),
        Commands::RotateDataKey => commands::vault::cmd_rotate_data_key(out, &path),
        Commands::Serve {
            relay,
            headless,
            frost_group,
            frost_relay,
        } => {
            let relay = relay.unwrap_or_else(|| cfg.default_relay().to_string());
            let frost_relay = frost_relay.unwrap_or_else(|| cfg.default_relay().to_string());
            commands::serve::cmd_serve(
                out,
                &path,
                &relay,
                headless,
                hidden,
                frost_group.as_deref(),
                &frost_relay,
            )
        }
        Commands::Wallet { command } => dispatch_wallet(out, &path, &cfg, command),
        Commands::Audit { command } => dispatch_audit(out, &path, command, hidden),
        Commands::Frost { command } => dispatch_frost(out, &path, &cfg, command),
        Commands::Bitcoin { command } => dispatch_bitcoin(out, &path, command),
        Commands::Enclave { command } => dispatch_enclave(out, &path, command),
        Commands::Agent { command } => dispatch_agent(out, &path, command, hidden),
        Commands::Config { command } => dispatch_config(out, &cfg, command),
        Commands::Migrate { command } => dispatch_migrate(out, &path, command, hidden),
    }
}

fn dispatch_migrate(
    out: &Output,
    path: &std::path::Path,
    command: Option<MigrateCommands>,
    hidden: bool,
) -> Result<()> {
    match command {
        None => commands::migrate::cmd_migrate(out, path, hidden),
        Some(MigrateCommands::Status) => commands::migrate::cmd_migrate_status(out, path, hidden),
    }
}

fn dispatch_agent(
    out: &Output,
    path: &std::path::Path,
    command: AgentCommands,
    hidden: bool,
) -> Result<()> {
    match command {
        AgentCommands::Mcp { key } => commands::agent::cmd_agent_mcp(out, path, &key, hidden),
    }
}

fn dispatch_audit(
    out: &Output,
    path: &std::path::Path,
    command: AuditCommands,
    hidden: bool,
) -> Result<()> {
    match command {
        AuditCommands::List { limit } => commands::audit::cmd_audit_list(out, path, limit, hidden),
        AuditCommands::Export { output } => {
            commands::audit::cmd_audit_export(out, path, output.as_deref(), hidden)
        }
        AuditCommands::Verify => commands::audit::cmd_audit_verify(out, path, hidden),
        AuditCommands::Retention {
            max_entries,
            max_days,
            apply,
        } => commands::audit::cmd_audit_retention(out, path, max_entries, max_days, apply, hidden),
        AuditCommands::Stats => commands::audit::cmd_audit_stats(out, path, hidden),
    }
}

fn dispatch_frost(
    out: &Output,
    path: &std::path::Path,
    cfg: &Config,
    command: FrostCommands,
) -> Result<()> {
    match command {
        FrostCommands::Generate {
            threshold,
            shares,
            name,
        } => commands::frost::cmd_frost_generate(out, path, threshold, shares, &name),
        FrostCommands::Split {
            key,
            threshold,
            shares,
        } => commands::frost::cmd_frost_split(out, path, &key, threshold, shares),
        FrostCommands::List => commands::frost::cmd_frost_list(out, path),
        FrostCommands::Export {
            share,
            group,
            format,
        } => commands::frost::cmd_frost_export(out, path, share, &group, format),
        FrostCommands::Import => commands::frost::cmd_frost_import(out, path),
        FrostCommands::Sign {
            message,
            group,
            interactive,
            warden_url,
        } => commands::frost::cmd_frost_sign(
            out,
            path,
            &message,
            &group,
            interactive,
            warden_url.as_deref(),
        ),
        FrostCommands::Refresh { group } => commands::frost::cmd_frost_refresh(out, path, &group),
        FrostCommands::Network { command } => dispatch_frost_network(out, path, cfg, command),
        FrostCommands::Hardware { command } => dispatch_frost_hardware(out, path, command),
    }
}

fn dispatch_frost_network(
    out: &Output,
    path: &std::path::Path,
    cfg: &Config,
    command: FrostNetworkCommands,
) -> Result<()> {
    let default_relay = cfg.default_relay();
    match command {
        FrostNetworkCommands::Serve {
            group,
            relay,
            share,
            auto_contribute_descriptor,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_serve(
                out,
                path,
                &group,
                relay,
                share,
                auto_contribute_descriptor,
            )
        }
        FrostNetworkCommands::Peers { group, relay } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_peers(out, path, &group, relay)
        }
        FrostNetworkCommands::Dkg {
            group,
            threshold,
            participants,
            index,
            relay,
            hardware,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_dkg(
                out,
                &group,
                threshold,
                participants,
                index,
                relay,
                &hardware,
            )
        }
        FrostNetworkCommands::Sign {
            group,
            message,
            relay,
            share,
            hardware,
            warden_url,
            threshold,
            participants,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_sign(
                out,
                path,
                &group,
                &message,
                relay,
                share,
                hardware.as_deref(),
                warden_url.as_deref(),
                threshold,
                participants,
            )
        }
        FrostNetworkCommands::SignEvent {
            group,
            kind,
            content,
            relay,
            share,
            hardware,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_sign_event(
                out,
                path,
                &group,
                kind,
                &content,
                relay,
                share,
                hardware.as_deref(),
            )
        }
        FrostNetworkCommands::GroupCreate {
            name,
            threshold,
            participants,
            relay,
            participant_npub,
        } => {
            let relay = if relay.is_empty() {
                vec![default_relay.to_string()]
            } else {
                relay
            };
            commands::frost_network::cmd_frost_network_group_create(
                out,
                &name,
                threshold,
                participants,
                &relay,
                &participant_npub,
            )
        }
        FrostNetworkCommands::NoncePrecommit {
            group,
            relay,
            hardware,
            count,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_nonce_precommit(
                out, path, &group, relay, &hardware, count,
            )
        }
        FrostNetworkCommands::HealthCheck {
            group,
            relay,
            share,
            timeout,
        } => {
            let relay = relay.as_deref().unwrap_or(default_relay);
            commands::frost_network::cmd_frost_network_health_check(
                out, path, &group, relay, share, timeout,
            )
        }
    }
}

fn dispatch_frost_hardware(
    out: &Output,
    path: &std::path::Path,
    command: FrostHardwareCommands,
) -> Result<()> {
    match command {
        FrostHardwareCommands::Ping { device } => {
            commands::frost_hardware::cmd_frost_hardware_ping(out, &device)
        }
        FrostHardwareCommands::List { device } => {
            commands::frost_hardware::cmd_frost_hardware_list(out, &device)
        }
        FrostHardwareCommands::Import {
            device,
            group,
            share,
        } => commands::frost_hardware::cmd_frost_hardware_import(out, path, &device, &group, share),
        FrostHardwareCommands::Delete { device, group } => {
            commands::frost_hardware::cmd_frost_hardware_delete(out, &device, &group)
        }
        FrostHardwareCommands::Sign {
            device,
            group,
            session_id,
            commitments,
        } => commands::frost_hardware::cmd_frost_hardware_sign(
            out,
            &device,
            &group,
            &session_id,
            &commitments,
        ),
        FrostHardwareCommands::Export {
            device,
            group,
            output,
        } => commands::frost_hardware::cmd_frost_hardware_export(
            out,
            &device,
            &group,
            output.as_deref(),
        ),
    }
}

fn dispatch_bitcoin(out: &Output, path: &std::path::Path, command: BitcoinCommands) -> Result<()> {
    match command {
        BitcoinCommands::Address {
            key,
            count,
            network,
        } => commands::bitcoin::cmd_bitcoin_address(out, path, &key, count, &network),
        BitcoinCommands::Descriptor {
            key,
            account,
            network,
        } => commands::bitcoin::cmd_bitcoin_descriptor(out, path, &key, account, &network),
        BitcoinCommands::Sign {
            key,
            psbt,
            output,
            network,
        } => {
            commands::bitcoin::cmd_bitcoin_sign(out, path, &key, &psbt, output.as_deref(), &network)
        }
        BitcoinCommands::Analyze { psbt, network } => {
            commands::bitcoin::cmd_bitcoin_analyze(out, &psbt, &network)
        }
    }
}

fn dispatch_wallet(
    out: &Output,
    path: &std::path::Path,
    cfg: &Config,
    cmd: WalletCommands,
) -> Result<()> {
    match cmd {
        WalletCommands::List => commands::wallet::cmd_wallet_list(out, path),
        WalletCommands::Show { group } => commands::wallet::cmd_wallet_show(out, path, &group),
        WalletCommands::Export { group, format } => {
            commands::wallet::cmd_wallet_export(out, path, &group, &format)
        }
        WalletCommands::Descriptor { group, network } => {
            commands::wallet::cmd_wallet_descriptor(out, path, &group, &network)
        }
        WalletCommands::Delete { group } => commands::wallet::cmd_wallet_delete(out, path, &group),
        WalletCommands::AnnounceKeys {
            group,
            relay,
            share,
            xpub,
        } => {
            let relay = relay.as_deref().unwrap_or_else(|| cfg.default_relay());
            commands::wallet::cmd_wallet_announce_keys(out, path, &group, relay, share, &xpub)
        }
        WalletCommands::Propose {
            group,
            network,
            relay,
            share,
            recovery,
            timeout,
        } => {
            let relay = relay.as_deref().unwrap_or_else(|| cfg.default_relay());
            commands::wallet::cmd_wallet_propose(
                out, path, &group, &network, relay, share, &recovery, timeout,
            )
        }
    }
}

fn dispatch_enclave(out: &Output, path: &std::path::Path, command: EnclaveCommands) -> Result<()> {
    match command {
        EnclaveCommands::Status { cid, local } => {
            commands::enclave::cmd_enclave_status(out, cid, local)
        }
        EnclaveCommands::Verify {
            cid,
            pcr0,
            pcr1,
            pcr2,
            local,
        } => commands::enclave::cmd_enclave_verify(
            out,
            cid,
            pcr0.as_deref(),
            pcr1.as_deref(),
            pcr2.as_deref(),
            local,
        ),
        EnclaveCommands::GenerateKey { name, cid, local } => {
            commands::enclave::cmd_enclave_generate_key(out, &name, cid, local)
        }
        EnclaveCommands::Sign {
            key,
            message,
            cid,
            local,
        } => commands::enclave::cmd_enclave_sign(out, &key, &message, cid, local),
        EnclaveCommands::ImportKey {
            name,
            from_vault,
            cid,
            local,
        } => commands::enclave::cmd_enclave_import_key(
            out,
            path,
            &name,
            from_vault.as_deref(),
            cid,
            local,
        ),
    }
}

fn dispatch_config(out: &Output, cfg: &Config, command: ConfigCommands) -> Result<()> {
    match command {
        ConfigCommands::Show => {
            let path = Config::default_path()?;
            out.header("Configuration");
            out.field("Config file", &path.display().to_string());
            out.field("Exists", &path.exists().to_string());
            out.newline();
            let vault_path_str = match cfg.vault_path() {
                Ok(p) => p.display().to_string(),
                Err(e) => format!("(error: {e})"),
            };
            out.field("vault_path", &vault_path_str);
            out.field("argon2_profile", &cfg.argon2_profile.to_string());
            out.field("log_level", &cfg.log_level.to_string());
            let relays = if cfg.relays.is_empty() {
                "(default: wss://nos.lol)".to_string()
            } else {
                cfg.relays.join(", ")
            };
            out.field("relays", &relays);
            out.field("timeout", &format!("{}s", cfg.timeout_secs()));
            Ok(())
        }
        ConfigCommands::Path => {
            let path = Config::default_path()?;
            out.info(&path.display().to_string());
            Ok(())
        }
        ConfigCommands::Init => {
            use keep_core::error::KeepError;
            use std::io::Write;

            let path = Config::default_path()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                        "create directory: {e}"
                    )))
                })?;
            }

            let mut file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    out.warn(&format!("Config file already exists: {}", path.display()));
                    return Ok(());
                }
                Err(e) => {
                    return Err(KeepError::StorageErr(keep_core::error::StorageError::io(
                        format!("create config: {e}"),
                    )));
                }
            };

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |e| {
                        KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                            "set permissions: {e}"
                        )))
                    },
                )?;
            }

            let example = include_str!("../contrib/config.toml.example");
            file.write_all(example.as_bytes()).map_err(|e| {
                KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                    "write config: {e}"
                )))
            })?;

            out.success(&format!("Created config file: {}", path.display()));
            Ok(())
        }
    }
}
