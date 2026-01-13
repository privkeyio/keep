// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

mod bunker;
mod commands;
mod output;
mod panic;
mod server;
mod signer;
mod tui;
#[cfg(feature = "warden")]
mod warden;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{Parser, Subcommand};
use tracing::debug;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use keep_core::crypto::disable_mlock;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("req-{:08x}", id)
}
use keep_core::default_keep_path;
use keep_core::error::Result;

use crate::output::Output;

#[derive(Parser)]
#[command(name = "keep")]
#[command(about = "Sovereign key management for Nostr and Bitcoin")]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    path: Option<PathBuf>,

    #[arg(long, global = true)]
    hidden: bool,

    #[arg(
        long,
        global = true,
        help = "Disable memory locking (accepts degraded security)"
    )]
    no_mlock: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = "100")]
        size: u64,
    },
    Generate {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    Import {
        #[arg(short, long, default_value = "imported")]
        name: String,
    },
    List,
    Export {
        #[arg(short, long)]
        name: String,
    },
    Delete {
        #[arg(short, long)]
        name: String,
    },
    Serve {
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(long)]
        headless: bool,
        #[arg(long)]
        frost_group: Option<String>,
        #[arg(long, default_value = "wss://nos.lol")]
        frost_relay: String,
    },
    Frost {
        #[command(subcommand)]
        command: FrostCommands,
    },
    Bitcoin {
        #[command(subcommand)]
        command: BitcoinCommands,
    },
    Enclave {
        #[command(subcommand)]
        command: EnclaveCommands,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
}

#[derive(Subcommand)]
enum AgentCommands {
    Mcp {
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand)]
enum FrostCommands {
    Generate {
        #[arg(short, long, default_value = "2")]
        threshold: u16,
        #[arg(short, long, default_value = "3")]
        shares: u16,
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    Split {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value = "2")]
        threshold: u16,
        #[arg(short, long, default_value = "3")]
        shares: u16,
    },
    List,
    Export {
        #[arg(short, long)]
        share: u16,
        #[arg(short, long)]
        group: String,
    },
    Import,
    Sign {
        #[arg(short, long)]
        message: String,
        #[arg(short, long)]
        group: String,
        #[arg(long)]
        interactive: bool,
        #[arg(
            long,
            help = "Warden URL for policy check (e.g., http://localhost:3000)"
        )]
        warden_url: Option<String>,
    },
    Network {
        #[command(subcommand)]
        command: FrostNetworkCommands,
    },
    Hardware {
        #[command(subcommand)]
        command: FrostHardwareCommands,
    },
}

#[derive(Subcommand)]
enum FrostNetworkCommands {
    Serve {
        #[arg(short, long)]
        group: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(short, long)]
        share: Option<u16>,
    },
    Peers {
        #[arg(short, long)]
        group: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
    },
    Dkg {
        #[arg(short, long, help = "Group name for the new keyset")]
        group: String,
        #[arg(
            short,
            long,
            default_value = "2",
            help = "Signature threshold (t in t-of-n)"
        )]
        threshold: u8,
        #[arg(short = 'n', long, default_value = "3", help = "Total participants")]
        participants: u8,
        #[arg(short = 'i', long, help = "Our participant index (1-indexed)")]
        index: u8,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyUSB0)")]
        hardware: String,
    },
    Sign {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyUSB0)")]
        hardware: Option<String>,
        #[arg(
            long,
            help = "Warden URL for policy check (e.g., http://localhost:3000)"
        )]
        warden_url: Option<String>,
        #[arg(
            short,
            long,
            help = "Signature threshold (required for hardware signing)"
        )]
        threshold: Option<u16>,
        #[arg(
            short = 'n',
            long,
            help = "Total participants (required for hardware signing)"
        )]
        participants: Option<u16>,
    },
    SignEvent {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        kind: u16,
        #[arg(short, long)]
        content: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyUSB0)")]
        hardware: Option<String>,
    },
    GroupCreate {
        #[arg(long, help = "Group name/identifier")]
        name: String,
        #[arg(short, long, help = "Signature threshold (t in t-of-n)")]
        threshold: u8,
        #[arg(short = 'n', long, help = "Total participants")]
        participants: u8,
        #[arg(
            short,
            long,
            default_value = "wss://nos.lol",
            help = "Relay URLs (can specify multiple)"
        )]
        relay: Vec<String>,
        #[arg(long, help = "Participant npubs (can specify multiple)")]
        participant_npub: Vec<String>,
    },
    NoncePrecommit {
        #[arg(short, long)]
        group: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(long, help = "Hardware signer device path")]
        hardware: String,
        #[arg(
            short,
            long,
            default_value = "10",
            help = "Number of nonces to pre-generate"
        )]
        count: u32,
    },
}

#[derive(Subcommand)]
enum FrostHardwareCommands {
    Ping {
        #[arg(short, long)]
        device: String,
    },
    List {
        #[arg(short, long)]
        device: String,
    },
    Import {
        #[arg(short, long)]
        device: String,
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        share: u16,
    },
    Delete {
        #[arg(short, long)]
        device: String,
        #[arg(short, long)]
        group: String,
    },
    Sign {
        #[arg(short, long)]
        device: String,
        #[arg(short, long)]
        group: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        commitments: String,
    },
}

#[derive(Subcommand)]
enum BitcoinCommands {
    Address {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value = "1")]
        count: u32,
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    Descriptor {
        #[arg(short, long)]
        key: String,
        #[arg(long, default_value = "0")]
        account: u32,
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        psbt: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    Analyze {
        #[arg(short, long)]
        psbt: String,
        #[arg(long, default_value = "testnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum EnclaveCommands {
    Status {
        #[arg(long, default_value = "16")]
        cid: u32,
        #[arg(long, help = "Use mock enclave for local testing")]
        local: bool,
    },
    Verify {
        #[arg(long, default_value = "16")]
        cid: u32,
        #[arg(long)]
        pcr0: Option<String>,
        #[arg(long)]
        pcr1: Option<String>,
        #[arg(long)]
        pcr2: Option<String>,
        #[arg(long, help = "Use mock enclave for local testing")]
        local: bool,
    },
    GenerateKey {
        #[arg(short, long)]
        name: String,
        #[arg(long, default_value = "16")]
        cid: u32,
        #[arg(long, help = "Use mock enclave for local testing")]
        local: bool,
    },
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
        #[arg(long, default_value = "16")]
        cid: u32,
        #[arg(long, help = "Use mock enclave for local testing")]
        local: bool,
    },
    ImportKey {
        #[arg(short, long)]
        name: String,
        #[arg(long, help = "Import from keep vault key")]
        from_vault: Option<String>,
        #[arg(long, default_value = "16")]
        cid: u32,
        #[arg(long, help = "Use mock enclave for local testing")]
        local: bool,
    },
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

    if cli.no_mlock {
        disable_mlock();
    }

    let path = match cli.path {
        Some(p) => p,
        None => default_keep_path()?,
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
        Commands::Serve {
            relay,
            headless,
            frost_group,
            frost_relay,
        } => commands::serve::cmd_serve(
            out,
            &path,
            &relay,
            headless,
            hidden,
            frost_group.as_deref(),
            &frost_relay,
        ),
        Commands::Frost { command } => dispatch_frost(out, &path, command),
        Commands::Bitcoin { command } => dispatch_bitcoin(out, &path, command),
        Commands::Enclave { command } => dispatch_enclave(out, &path, command),
        Commands::Agent { command } => dispatch_agent(out, &path, command, hidden),
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

fn dispatch_frost(out: &Output, path: &std::path::Path, command: FrostCommands) -> Result<()> {
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
        FrostCommands::Export { share, group } => {
            commands::frost::cmd_frost_export(out, path, share, &group)
        }
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
        FrostCommands::Network { command } => dispatch_frost_network(out, path, command),
        FrostCommands::Hardware { command } => dispatch_frost_hardware(out, path, command),
    }
}

fn dispatch_frost_network(
    out: &Output,
    path: &std::path::Path,
    command: FrostNetworkCommands,
) -> Result<()> {
    match command {
        FrostNetworkCommands::Serve {
            group,
            relay,
            share,
        } => commands::frost_network::cmd_frost_network_serve(out, path, &group, &relay, share),
        FrostNetworkCommands::Peers { group, relay } => {
            commands::frost_network::cmd_frost_network_peers(out, path, &group, &relay)
        }
        FrostNetworkCommands::Dkg {
            group,
            threshold,
            participants,
            index,
            relay,
            hardware,
        } => commands::frost_network::cmd_frost_network_dkg(
            out,
            &group,
            threshold,
            participants,
            index,
            &relay,
            &hardware,
        ),
        FrostNetworkCommands::Sign {
            group,
            message,
            relay,
            share,
            hardware,
            warden_url,
            threshold,
            participants,
        } => commands::frost_network::cmd_frost_network_sign(
            out,
            path,
            &group,
            &message,
            &relay,
            share,
            hardware.as_deref(),
            warden_url.as_deref(),
            threshold,
            participants,
        ),
        FrostNetworkCommands::SignEvent {
            group,
            kind,
            content,
            relay,
            share,
            hardware,
        } => commands::frost_network::cmd_frost_network_sign_event(
            out,
            path,
            &group,
            kind,
            &content,
            &relay,
            share,
            hardware.as_deref(),
        ),
        FrostNetworkCommands::GroupCreate {
            name,
            threshold,
            participants,
            relay,
            participant_npub,
        } => commands::frost_network::cmd_frost_network_group_create(
            out,
            &name,
            threshold,
            participants,
            &relay,
            &participant_npub,
        ),
        FrostNetworkCommands::NoncePrecommit {
            group,
            relay,
            hardware,
            count,
        } => commands::frost_network::cmd_frost_network_nonce_precommit(
            out, path, &group, &relay, &hardware, count,
        ),
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
