mod bunker;
mod output;
mod server;
mod signer;
mod tui;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use nostr_sdk::prelude::ToBech32;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::frost::ShareExport;
use keep_core::keys::bytes_to_npub;
use keep_core::{default_keep_path, Keep};

use crate::output::Output;
use crate::server::Server;

fn get_password(prompt: &str) -> Result<SecretString> {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        debug!("using password from KEEP_PASSWORD env var");
        return Ok(SecretString::from(pw));
    }
    let pw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .map_err(|e| KeepError::Other(format!("Failed to read password: {}", e)))?;
    Ok(SecretString::from(pw))
}

fn get_password_with_confirm(prompt: &str, confirm: &str) -> Result<SecretString> {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        debug!("using password from KEEP_PASSWORD env var");
        return Ok(SecretString::from(pw));
    }
    let pw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .with_confirmation(confirm, "Passwords don't match")
        .interact()
        .map_err(|e| KeepError::Other(format!("Failed to read password: {}", e)))?;
    Ok(SecretString::from(pw))
}

fn get_confirm(prompt: &str) -> Result<bool> {
    if std::env::var("KEEP_YES").is_ok() {
        return Ok(true);
    }
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|e| KeepError::Other(format!("Failed to read confirmation: {}", e)))
}

fn is_hidden_vault(path: &std::path::Path) -> bool {
    path.join("keep.vault").exists()
}

#[derive(Parser)]
#[command(name = "keep")]
#[command(about = "Sovereign key management for Nostr and Bitcoin")]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    path: Option<PathBuf>,

    #[arg(long, global = true)]
    hidden: bool,

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
    },
    Network {
        #[command(subcommand)]
        command: FrostNetworkCommands,
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
    Sign {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "wss://nos.lol")]
        relay: String,
        #[arg(short, long)]
        share: Option<u16>,
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

fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

fn main() {
    setup_panic_hook();

    ctrlc::set_handler(|| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        std::process::exit(130);
    })
    .ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    let out = Output::new();

    if let Err(e) = run(&out) {
        out.error(&e.to_string());
        std::process::exit(1);
    }
}

fn run(out: &Output) -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.path {
        Some(p) => p,
        None => default_keep_path()?,
    };
    let hidden = cli.hidden;

    debug!(path = %path.display(), hidden, "starting command");

    match cli.command {
        Commands::Init { size } => cmd_init(out, &path, hidden, size),
        Commands::Generate { name } => cmd_generate(out, &path, &name, hidden),
        Commands::Import { name } => cmd_import(out, &path, &name, hidden),
        Commands::List => cmd_list(out, &path, hidden),
        Commands::Export { name } => cmd_export(out, &path, &name, hidden),
        Commands::Delete { name } => cmd_delete(out, &path, &name, hidden),
        Commands::Serve {
            relay,
            headless,
            frost_group,
            frost_relay,
        } => cmd_serve(
            out,
            &path,
            &relay,
            headless,
            hidden,
            frost_group.as_deref(),
            &frost_relay,
        ),
        Commands::Frost { command } => cmd_frost(out, &path, command),
        Commands::Bitcoin { command } => cmd_bitcoin(out, &path, command),
        Commands::Enclave { command } => cmd_enclave(out, &path, command),
        Commands::Agent { command } => cmd_agent(out, &path, command, hidden),
    }
}

fn cmd_agent(out: &Output, path: &Path, command: AgentCommands, hidden: bool) -> Result<()> {
    match command {
        AgentCommands::Mcp { key } => cmd_agent_mcp(out, path, &key, hidden),
    }
}

fn cmd_agent_mcp(out: &Output, path: &Path, key_name: &str, hidden: bool) -> Result<()> {
    use keep_agent::mcp::McpServer;
    use keep_agent::scope::SessionScope;
    use keep_agent::session::SessionConfig;
    use std::io::{BufRead, Write};

    if hidden {
        return Err(KeepError::Other(
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
        .map_err(|e| KeepError::Other(format!("Failed to create runtime: {}", e)))?;

    let (token, session_id) = rt.block_on(async {
        let (token, session_id) = server
            .create_session(config)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to create session: {}", e)))?;
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
        let line = line.map_err(|e| KeepError::Other(format!("Read error: {}", e)))?;
        if line.trim().is_empty() {
            continue;
        }

        let response = server.handle_request(&line);
        writeln!(stdout, "{}", response)
            .map_err(|e| KeepError::Other(format!("Write error: {}", e)))?;
        stdout
            .flush()
            .map_err(|e| KeepError::Other(format!("Flush error: {}", e)))?;
    }

    Ok(())
}

fn cmd_frost(out: &Output, path: &Path, command: FrostCommands) -> Result<()> {
    match command {
        FrostCommands::Generate {
            threshold,
            shares,
            name,
        } => cmd_frost_generate(out, path, threshold, shares, &name),
        FrostCommands::Split {
            key,
            threshold,
            shares,
        } => cmd_frost_split(out, path, &key, threshold, shares),
        FrostCommands::List => cmd_frost_list(out, path),
        FrostCommands::Export { share, group } => cmd_frost_export(out, path, share, &group),
        FrostCommands::Import => cmd_frost_import(out, path),
        FrostCommands::Sign {
            message,
            group,
            interactive,
        } => cmd_frost_sign(out, path, &message, &group, interactive),
        FrostCommands::Network { command } => cmd_frost_network(out, path, command),
    }
}

fn cmd_frost_network(out: &Output, path: &Path, command: FrostNetworkCommands) -> Result<()> {
    match command {
        FrostNetworkCommands::Serve {
            group,
            relay,
            share,
        } => cmd_frost_network_serve(out, path, &group, &relay, share),
        FrostNetworkCommands::Peers { group, relay } => {
            cmd_frost_network_peers(out, path, &group, &relay)
        }
        FrostNetworkCommands::Sign {
            group,
            message,
            relay,
            share,
        } => cmd_frost_network_sign(out, path, &group, &message, &relay, share),
        FrostNetworkCommands::SignEvent {
            group,
            kind,
            content,
            relay,
            share,
        } => cmd_frost_network_sign_event(out, path, &group, kind, &content, &relay, share),
    }
}

fn cmd_frost_network_serve(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
) -> Result<()> {
    debug!(group = group_npub, relay, share = ?share_index, "starting FROST network node");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };
    let threshold = share.metadata.threshold;
    let share_index = share.metadata.identifier;
    let total_shares = share.metadata.total_shares;

    out.newline();
    out.header("FROST Network Node");
    out.field("Group", group_npub);
    out.field("Share", &share_index.to_string());
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        out.info("Starting FROST coordination node...");

        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let npub = node.pubkey().to_bech32().unwrap_or_default();
        out.field("Node pubkey", &npub);
        out.newline();
        out.info("Listening for FROST messages... (Ctrl+C to stop)");

        let mut event_rx = node.subscribe();
        let event_task = tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { share_index, name }) => {
                        let name_str = name.unwrap_or_else(|| "unnamed".to_string());
                        eprintln!("Peer discovered: Share {} ({})", share_index, name_str);
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SignatureComplete {
                        session_id,
                        signature,
                    }) => {
                        eprintln!(
                            "Signature complete for session {}: {}",
                            hex::encode(&session_id[..8]),
                            hex::encode(signature)
                        );
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SigningFailed { session_id, error }) => {
                        eprintln!(
                            "Signing failed for session {}: {}",
                            hex::encode(&session_id[..8]),
                            error
                        );
                    }
                    Err(_) => break,
                    _ => {}
                }
            }
        });

        node.run()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        event_task.abort();

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn cmd_frost_network_peers(out: &Output, path: &Path, group_npub: &str, relay: &str) -> Result<()> {
    debug!(group = group_npub, relay, "checking FROST peers");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = keep.frost_get_share(&group_pubkey)?;

    out.newline();
    out.header("FROST Network Peers");
    out.field("Group", group_npub);
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let spinner = out.spinner("Connecting and discovering peers...");

        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!("FROST node error: {}", e);
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        spinner.finish();
        node_handle.abort();

        let status = node.peer_status();

        if status.is_empty() {
            out.info("No peers discovered yet.");
            out.info("Run 'keep frost network serve' on other devices first.");
        } else {
            out.table_header(&[("SHARE", 8), ("STATUS", 10), ("NAME", 20)]);

            for (share_index, peer_status, name) in status {
                let status_str = match peer_status {
                    keep_frost_net::PeerStatus::Online => "Online",
                    keep_frost_net::PeerStatus::Offline => "Offline",
                    keep_frost_net::PeerStatus::Unknown => "Unknown",
                };
                let name_str = name.unwrap_or_else(|| "-".to_string());
                out.table_row(&[
                    (&share_index.to_string(), 8, false),
                    (status_str, 10, false),
                    (&name_str, 20, false),
                ]);
            }
        }

        out.newline();
        out.info(&format!("{} peer(s) online", node.online_peers()));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn cmd_frost_network_sign(
    out: &Output,
    path: &Path,
    group_npub: &str,
    message: &str,
    relay: &str,
    share_index: Option<u16>,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = if let Some(idx) = share_index {
        keep.frost_get_share_by_index(&group_pubkey, idx)?
    } else {
        keep.frost_get_share(&group_pubkey)?
    };

    out.newline();
    out.header("FROST Network Sign");
    out.field("Group", group_npub);
    out.field(
        "Share",
        &format!("{} ({})", share.metadata.identifier, share.metadata.name),
    );
    out.field(
        "Threshold",
        &format!(
            "{}-of-{}",
            share.metadata.threshold, share.metadata.total_shares
        ),
    );
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;
    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        out.info("Starting FROST coordination node...");
        out.field(
            "Node pubkey",
            &node.pubkey().to_bech32().unwrap_or_default(),
        );
        out.newline();

        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _handle = tokio::spawn(async move {
            let _ = node_clone.run().await;
        });

        out.info("Discovering peers...");
        for i in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if node.online_peers() > 0 {
                break;
            }
            if i < 11 {
                out.info(&format!("  Waiting for peers... ({}/12)", i + 1));
            }
        }

        if node.online_peers() == 0 {
            return Err(KeepError::Frost("No peers online after 24s.".into()));
        }

        out.success(&format!("Found {} online peer(s)", node.online_peers()));
        out.newline();

        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let spinner = out.spinner("Requesting signature from network...");
        let signature = node
            .request_signature(message.as_bytes().to_vec(), "raw")
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.newline();
        out.success("Signature complete!");
        out.field("Signature", &hex::encode(signature));
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn cmd_frost_network_sign_event(
    out: &Output,
    path: &Path,
    group_npub: &str,
    kind: u16,
    content: &str,
    relay: &str,
    share_index: Option<u16>,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = if let Some(idx) = share_index {
        keep.frost_get_share_by_index(&group_pubkey, idx)?
    } else {
        keep.frost_get_share(&group_pubkey)?
    };
    let pubkey_hex = hex::encode(group_pubkey);

    out.newline();
    out.header("FROST Network Sign Event");
    out.field("Group", group_npub);
    out.field(
        "Share",
        &format!("{} ({})", share.metadata.identifier, share.metadata.name),
    );
    out.field(
        "Threshold",
        &format!(
            "{}-of-{}",
            share.metadata.threshold, share.metadata.total_shares
        ),
    );
    out.field("Relay", relay);
    out.field("Kind", &kind.to_string());
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;
    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        out.info("Starting FROST coordination node...");
        out.field(
            "Node pubkey",
            &node.pubkey().to_bech32().unwrap_or_default(),
        );
        out.newline();

        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _handle = tokio::spawn(async move {
            let _ = node_clone.run().await;
        });

        out.info("Discovering peers...");
        for i in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if node.online_peers() > 0 {
                break;
            }
            if i < 11 {
                out.info(&format!("  Waiting for peers... ({}/12)", i + 1));
            }
        }

        if node.online_peers() == 0 {
            return Err(KeepError::Frost("No peers online after 24s.".into()));
        }

        out.success(&format!("Found {} online peer(s)", node.online_peers()));
        out.newline();

        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| KeepError::Other(format!("System clock error: {}", e)))?
            .as_secs();
        let tags: Vec<Vec<String>> = vec![];
        let serialized = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);

        let mut hasher = Sha256::new();
        hasher.update(serialized.to_string().as_bytes());
        let event_id = hasher.finalize();
        let event_id_hex = hex::encode(event_id);

        out.field("Event ID", &event_id_hex);

        let spinner = out.spinner("Requesting signature from network...");
        let signature = node
            .request_signature(event_id.to_vec(), "nostr_event")
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        let signed_event = serde_json::json!({
            "id": event_id_hex,
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": hex::encode(signature)
        });

        out.newline();
        out.success("Event signed!");
        out.newline();
        let output = serde_json::to_string_pretty(&signed_event)
            .map_err(|e| KeepError::Other(format!("Failed to serialize event: {}", e)))?;
        println!("{}", output);
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

fn cmd_frost_generate(
    out: &Output,
    path: &Path,
    threshold: u16,
    total_shares: u16,
    name: &str,
) -> Result<()> {
    debug!(threshold, total_shares, name, "generating FROST key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating FROST key shares...");
    let shares = keep.frost_generate(threshold, total_shares, name)?;
    spinner.finish();

    if shares.is_empty() {
        return Err(KeepError::Frost(
            "no shares returned from frost_generate".into(),
        ));
    }

    let group_pubkey = shares[0].group_pubkey();
    let npub = bytes_to_npub(group_pubkey);

    out.newline();
    out.success("Generated FROST key group!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.newline();

    for share in &shares {
        out.info(&format!(
            "Share {}: stored locally",
            share.metadata.identifier
        ));
    }

    out.newline();
    out.warn("BACKUP: Export shares to different locations for recovery!");

    Ok(())
}

fn cmd_frost_split(
    out: &Output,
    path: &Path,
    key_name: &str,
    threshold: u16,
    total_shares: u16,
) -> Result<()> {
    debug!(
        key_name,
        threshold, total_shares, "splitting key into FROST shares"
    );

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Splitting key into FROST shares...");
    let shares = keep.frost_split(key_name, threshold, total_shares)?;
    spinner.finish();

    if shares.is_empty() {
        return Err(KeepError::Frost(
            "no shares returned from frost_split".into(),
        ));
    }

    let group_pubkey = shares[0].group_pubkey();
    let npub = bytes_to_npub(group_pubkey);

    out.newline();
    out.success("Split key into FROST shares!");
    out.key_field("Pubkey (preserved)", &npub);
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.newline();

    for share in &shares {
        out.info(&format!(
            "Share {}: stored locally",
            share.metadata.identifier
        ));
    }

    out.newline();
    out.warn("BACKUP: Export shares to different locations for recovery!");

    Ok(())
}

fn cmd_frost_list(out: &Output, path: &Path) -> Result<()> {
    debug!("listing FROST shares");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let shares = keep.frost_list_shares()?;

    if shares.is_empty() {
        out.newline();
        out.info("No FROST shares found. Use 'keep frost generate' to create some.");
        return Ok(());
    }

    out.table_header(&[("NAME", 16), ("ID", 6), ("THRESHOLD", 12), ("PUBKEY", 28)]);

    for share in &shares {
        let npub = bytes_to_npub(&share.metadata.group_pubkey);
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&share.metadata.name, 16, false),
            (&share.metadata.identifier.to_string(), 6, false),
            (
                &format!(
                    "{}-of-{}",
                    share.metadata.threshold, share.metadata.total_shares
                ),
                12,
                false,
            ),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} share(s) total", shares.len()));

    Ok(())
}

fn cmd_frost_export(out: &Output, path: &Path, identifier: u16, group_npub: &str) -> Result<()> {
    debug!(identifier, group_npub, "exporting FROST share");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let export_password =
        get_password_with_confirm("Enter passphrase for share export", "Confirm passphrase")?;

    let spinner = out.spinner("Encrypting share for export...");
    let export =
        keep.frost_export_share(&group_pubkey, identifier, export_password.expose_secret())?;
    spinner.finish();

    let json = export.to_json()?;

    out.newline();
    out.success("Share exported!");
    out.newline();
    out.info("Copy this export data (JSON format):");
    out.newline();
    println!("{}", json);

    Ok(())
}

fn cmd_frost_import(out: &Output, path: &Path) -> Result<()> {
    debug!("importing FROST share");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    out.info("Paste the share export JSON (end with empty line):");

    let mut json = String::new();
    loop {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| KeepError::Other(format!("Failed to read input: {}", e)))?;
        if line.trim().is_empty() {
            break;
        }
        json.push_str(&line);
    }

    let export = ShareExport::from_json(json.trim())?;
    let import_password = get_password("Enter share passphrase")?;

    let spinner = out.spinner("Decrypting and importing share...");
    keep.frost_import_share(&export, import_password.expose_secret())?;
    spinner.finish();

    out.newline();
    out.success(&format!(
        "Imported share {} for group {}",
        export.identifier, export.group_pubkey
    ));

    Ok(())
}

fn cmd_frost_sign(
    out: &Output,
    path: &Path,
    message_hex: &str,
    group_npub: &str,
    interactive: bool,
) -> Result<()> {
    debug!(
        message = message_hex,
        group = group_npub,
        interactive,
        "FROST signing"
    );

    let message =
        hex::decode(message_hex).map_err(|_| KeepError::Other("Invalid message hex".into()))?;

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let shares = keep.frost_list_shares()?;
    let our_shares: Vec<_> = shares
        .iter()
        .filter(|s| s.metadata.group_pubkey == group_pubkey)
        .collect();

    if our_shares.is_empty() {
        return Err(KeepError::KeyNotFound(format!(
            "No shares found for group {}",
            group_npub
        )));
    }

    let threshold = our_shares[0].metadata.threshold;
    let total = our_shares[0].metadata.total_shares;

    if interactive {
        return cmd_frost_sign_interactive(out, &keep, &group_pubkey, &message, threshold, total);
    }

    if our_shares.len() < threshold as usize {
        return Err(KeepError::Other(format!(
            "Need {} shares to sign, only {} local. Use --interactive for multi-device signing.",
            threshold,
            our_shares.len()
        )));
    }

    out.info(&format!(
        "Signing with {}-of-{} local shares",
        threshold, total
    ));

    let spinner = out.spinner("Generating signature...");
    let sig_bytes = keep.frost_sign(&group_pubkey, &message)?;
    spinner.finish();

    out.newline();
    out.success("Signature generated!");
    out.newline();
    println!("{}", hex::encode(sig_bytes));

    Ok(())
}

fn cmd_frost_sign_interactive(
    out: &Output,
    keep: &Keep,
    group_pubkey: &[u8; 32],
    message: &[u8],
    threshold: u16,
    total: u16,
) -> Result<()> {
    use frost::{round1, round2, Identifier, SigningPackage};
    use frost_secp256k1_tr as frost;
    use keep_core::frost::FrostMessage;
    use std::collections::BTreeMap;
    use std::io::{BufRead, Write};

    out.info(&format!(
        "Interactive FROST signing: {}-of-{}",
        threshold, total
    ));
    out.newline();

    let share = keep.frost_get_share(group_pubkey)?;
    let kp = share.key_package()?;
    let our_id = *kp.identifier();
    let our_id_u16 = share.metadata.identifier;

    let session_id: [u8; 32] = keep_core::crypto::blake2b_256(message);

    out.info("Round 1: Generating commitment...");
    let (our_nonces, our_commitment) =
        round1::commit(kp.signing_share(), &mut frost::rand_core::OsRng);

    let commit_bytes = our_commitment
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Serialize commitment: {}", e)))?;
    let commit_msg = FrostMessage::commitment(&session_id, our_id_u16, &commit_bytes);
    let commit_json = commit_msg.to_json()?;

    out.newline();
    out.info("Send this commitment to other signers:");
    println!("{}", commit_json);
    out.newline();

    let mut commitments: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    commitments.insert(our_id, our_commitment);

    let needed = threshold as usize - 1;
    out.info(&format!(
        "Waiting for {} commitment(s). Paste each on one line:",
        needed
    ));

    let stdin = std::io::stdin();
    for i in 0..needed {
        print!("[{}/{}] ", i + 1, needed);
        std::io::stdout().flush().ok();

        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| KeepError::Other(format!("Read error: {}", e)))?;

        let msg = FrostMessage::from_json(line.trim())?;
        if msg.session_id != hex::encode(session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let commit = round1::SigningCommitments::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid commitment: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;
        commitments.insert(id, commit);
    }

    out.newline();
    out.info("Round 2: Generating signature share...");

    let signing_package = SigningPackage::new(commitments.clone(), message);
    let our_sig_share = round2::sign(&signing_package, &our_nonces, &kp)
        .map_err(|e| KeepError::Frost(format!("Sign failed: {}", e)))?;

    let share_bytes = our_sig_share.serialize();
    let share_msg = FrostMessage::signature_share(&session_id, our_id_u16, &share_bytes);
    let share_json = share_msg.to_json()?;

    out.newline();
    out.info("Send this signature share to the coordinator:");
    println!("{}", share_json);
    out.newline();

    let mut sig_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    sig_shares.insert(our_id, our_sig_share);

    out.info(&format!("Waiting for {} signature share(s):", needed));

    for i in 0..needed {
        print!("[{}/{}] ", i + 1, needed);
        std::io::stdout().flush().ok();

        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| KeepError::Other(format!("Read error: {}", e)))?;

        let msg = FrostMessage::from_json(line.trim())?;
        if msg.session_id != hex::encode(session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let sig_share = round2::SignatureShare::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid signature share: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;
        sig_shares.insert(id, sig_share);
    }

    out.newline();
    out.info("Aggregating signature...");

    let pubkey_pkg = share.pubkey_package()?;
    let signature = frost::aggregate(&signing_package, &sig_shares, &pubkey_pkg)
        .map_err(|e| KeepError::Frost(format!("Aggregation failed: {}", e)))?;

    let serialized = signature
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Serialize signature: {}", e)))?;
    let bytes = serialized.as_slice();
    if bytes.len() != 64 {
        return Err(KeepError::Frost("Invalid signature length".into()));
    }

    out.newline();
    out.success("Signature generated!");
    out.newline();
    println!("{}", hex::encode(bytes));

    Ok(())
}

fn cmd_init(out: &Output, path: &Path, hidden: bool, size_mb: u64) -> Result<()> {
    if hidden {
        out.hidden_banner();
    }

    out.header("Creating new Keep");
    out.field("Path", &path.display().to_string());
    out.newline();

    let (outer_prompt, outer_confirm) = if hidden {
        ("Enter OUTER password", "Confirm OUTER password")
    } else {
        ("Enter password", "Confirm password")
    };

    let outer_password = get_password_with_confirm(outer_prompt, outer_confirm)?;

    if outer_password.expose_secret().len() < 8 {
        return Err(KeepError::Other(
            "Password must be at least 8 characters".into(),
        ));
    }

    let hidden_password: Option<SecretString> = if hidden {
        out.newline();
        let hp = if let Ok(hp_env) = std::env::var("KEEP_HIDDEN_PASSWORD") {
            debug!("using hidden password from KEEP_HIDDEN_PASSWORD env var");
            SecretString::from(hp_env)
        } else {
            let pw = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter HIDDEN password (must be different!)")
                .with_confirmation("Confirm HIDDEN password", "Passwords don't match")
                .interact()
                .unwrap();
            SecretString::from(pw)
        };

        if hp.expose_secret() == outer_password.expose_secret() {
            return Err(KeepError::Other(
                "HIDDEN password must be DIFFERENT from OUTER password!".into(),
            ));
        }

        if hp.expose_secret().len() < 8 {
            return Err(KeepError::Other(
                "Password must be at least 8 characters".into(),
            ));
        }

        Some(hp)
    } else {
        None
    };

    let spinner = out.spinner("Deriving keys and creating volume...");
    let total_size = size_mb * 1024 * 1024;

    info!(size_mb, hidden, "creating keep");

    if hidden {
        keep_core::hidden::HiddenStorage::create(
            path,
            outer_password.expose_secret(),
            hidden_password.as_ref().map(|s| s.expose_secret()),
            total_size,
            0.2,
        )?;
    } else {
        Keep::create(path, outer_password.expose_secret())?;
    }

    spinner.finish();
    out.newline();
    out.success("Keep created successfully!");

    if hidden {
        out.hidden_notes();
    } else {
        out.init_notes();
    }

    Ok(())
}

fn cmd_generate(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_generate_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_generate_outer(out, path, name);
    }

    debug!(name, "generating key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let pubkey = keep.generate_key(name)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated");

    out.newline();
    out.success("Generated new key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_generate_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated in outer volume");

    out.newline();
    out.success("Generated new key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_generate_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key generated in hidden volume");

    out.newline();
    out.success("Generated new key in hidden volume!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_import_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_import_outer(out, path, name);
    }

    debug!(name, "importing key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let nsec = get_password("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let pubkey = keep.import_nsec(nsec.expose_secret(), name)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported");

    out.newline();
    out.success("Imported key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let nsec = get_password("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(nsec.expose_secret())?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported to outer volume");

    out.newline();
    out.success("Imported key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let nsec = get_password("Enter nsec")?;

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(nsec.expose_secret())?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(
        pubkey,
        KeyType::Nostr,
        name.to_string(),
        encrypted.to_bytes(),
    );
    storage.store_key(&record)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported to hidden volume");

    out.newline();
    out.success("Imported key to hidden volume!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_list(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_list_hidden(out, path);
    }
    if is_hidden_vault(path) {
        return cmd_list_outer(out, path);
    }

    debug!("listing keys");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let keys = keep.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found. Use 'keep generate' to create one.");
        return Ok(());
    }

    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

fn cmd_list_outer(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!("listing keys in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found. Use 'keep generate' to create one.");
        return Ok(());
    }

    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

fn cmd_list_hidden(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    debug!("listing keys in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;

    if keys.is_empty() {
        out.newline();
        out.info("No keys found in hidden volume. Use 'keep --hidden generate' to create one.");
        return Ok(());
    }

    out.hidden_label();
    out.table_header(&[("NAME", 20), ("TYPE", 20), ("PUBKEY", 28)]);

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&key.name, 20, false),
            (&format!("{:?}", key.key_type), 20, false),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} key(s) total", keys.len()));

    Ok(())
}

fn cmd_export(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_export_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_export_outer(out, path, name);
    }

    debug!(name, "exporting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let keypair = slot.to_nostr_keypair()?;

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::NostrKeypair;

    debug!(name, "exporting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
    let secret_bytes = crypto::decrypt(&encrypted, data_key)?;

    let mut secret = [0u8; 32];
    let decrypted = secret_bytes.as_slice()?;
    secret.copy_from_slice(&decrypted);
    let keypair = NostrKeypair::from_secret_bytes(&secret)?;
    secret.zeroize();

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported from outer volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keys::NostrKeypair;

    debug!(name, "exporting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
    let secret_bytes = crypto::decrypt(&encrypted, data_key)?;

    let mut secret = [0u8; 32];
    let decrypted = secret_bytes.as_slice()?;
    secret.copy_from_slice(&decrypted);
    let keypair = NostrKeypair::from_secret_bytes(&secret)?;
    secret.zeroize();

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?")? {
        warn!(name, "nsec exported from hidden volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_delete(out: &Output, path: &Path, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_delete_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_delete_outer(out, path, name);
    }

    debug!(name, "deleting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let pubkey = slot.pubkey;

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name))? {
        out.info("Cancelled.");
        return Ok(());
    }

    keep.delete_key(&pubkey)?;
    info!(name, "key deleted");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_outer(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;

    debug!(name, "deleting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let id = crypto::blake2b_256(&record.pubkey);

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name))? {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from outer volume");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_hidden(out: &Output, path: &Path, name: &str) -> Result<()> {
    use keep_core::crypto;
    use keep_core::hidden::HiddenStorage;

    debug!(name, "deleting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let id = crypto::blake2b_256(&record.pubkey);

    if !get_confirm(&format!(
        "Delete key '{}' from hidden volume? This cannot be undone!",
        name
    ))? {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from hidden volume");

    out.newline();
    out.success(&format!("Deleted key from hidden volume: {}", name));

    Ok(())
}

fn cmd_serve(
    out: &Output,
    path: &Path,
    relay: &str,
    headless: bool,
    hidden: bool,
    frost_group: Option<&str>,
    frost_relay: &str,
) -> Result<()> {
    use crate::signer::{FrostSigner, NetworkFrostSigner};

    if hidden {
        return cmd_serve_hidden(out, path, relay, headless);
    }
    if is_hidden_vault(path) {
        return cmd_serve_outer(out, path, relay, headless);
    }

    debug!(relay, headless, ?frost_group, "starting server");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    if let Some(group_npub) = frost_group {
        let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
        let share = keep.frost_get_share(&group_pubkey)?;
        let threshold = share.metadata.threshold;
        let total_shares = share.metadata.total_shares;

        out.newline();
        out.header("NIP-46 Bunker (FROST Network Mode)");
        out.field("Group", group_npub);
        out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
        out.field("FROST Relay", frost_relay);
        out.field("Bunker Relay", relay);
        out.newline();

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

        return rt.block_on(async {
            out.info("Connecting to FROST network...");
            let node = keep_frost_net::KfpNode::new(share, vec![frost_relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?;

            node.announce()
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?;

            let node = std::sync::Arc::new(node);
            let node_for_task = node.clone();
            let _node_handle = tokio::spawn(async move {
                if let Err(e) = node_for_task.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            });

            let net_signer = NetworkFrostSigner::with_shared_node(group_pubkey, node);
            out.success("Connected to FROST network");

            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();

            let mut server =
                Server::new_network_frost(net_signer, transport_key, relay, None).await?;
            let bunker_url = server.bunker_url();
            out.field("Bunker URL", &bunker_url);
            out.newline();
            out.info("Listening for NIP-46 requests...");
            out.info("(Sign requests will coordinate with FROST peers)");
            server.run().await
        });
    }

    let shares = keep.frost_list_shares()?;
    let frost_signer = if !shares.is_empty() {
        let first_group = &shares[0].metadata.group_pubkey;
        let group_shares: Vec<_> = shares
            .iter()
            .filter(|s| &s.metadata.group_pubkey == first_group)
            .cloned()
            .collect();
        let threshold = group_shares[0].metadata.threshold as usize;
        let total = group_shares.len();
        if total >= threshold {
            let data_key = keep.data_key()?;
            let group_pubkey = *first_group;
            match FrostSigner::new(group_pubkey, group_shares, data_key) {
                Ok(signer) => {
                    out.info(&format!("Using FROST signing ({}-of-{})", threshold, total));
                    Some(signer)
                }
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
    let rt = tokio::runtime::Runtime::new().unwrap();

    if headless {
        rt.block_on(async {
            let mut server = if let Some(frost) = frost_signer {
                let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
                Server::new_frost(frost, transport_key, relay, None).await?
            } else {
                Server::new(keyring, relay, None).await?
            };
            info!(relay, bunker_url = %server.bunker_url(), "server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub, keyring_for_tui, _, transport_key_for_tui) = rt.block_on(async {
        if let Some(ref frost) = frost_signer {
            let transport_key: [u8; 32] = keep_core::crypto::random_bytes();
            let server = Server::new_frost(frost.clone(), transport_key, relay, None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
                true,
                Some(transport_key),
            ))
        } else {
            let server = Server::new(keyring.clone(), relay, None).await?;
            Ok::<_, KeepError>((
                server.bunker_url(),
                server.pubkey().to_bech32().unwrap_or_default(),
                keyring.clone(),
                false,
                None,
            ))
        }
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server = if let (Some(frost), Some(transport_key)) =
                (frost_signer, transport_key_for_tui)
            {
                match Server::new_frost(
                    frost,
                    transport_key,
                    &relay_clone,
                    Some(tui_tx_clone.clone()),
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                }
            } else {
                match Server::new(keyring_for_tui, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}

fn cmd_serve_outer(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keyring::Keyring;

    debug!(relay, headless, "starting server from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(password.expose_secret())?;
    spinner.finish();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        let decrypted = secret_bytes.as_slice()?;
        secret.copy_from_slice(&decrypted);
        keyring.load_key(record.pubkey, secret, record.key_type, record.name)?;
        secret.zeroize();
    }

    let keyring = Arc::new(Mutex::new(keyring));
    let rt = tokio::runtime::Runtime::new().unwrap();

    if headless {
        rt.block_on(async {
            let mut server = Server::new(keyring, relay, None).await?;
            info!(relay, bunker_url = %server.bunker_url(), "server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub) = rt.block_on(async {
        let server = Server::new(keyring.clone(), relay, None).await?;
        Ok::<_, KeepError>((
            server.bunker_url(),
            server.pubkey().to_bech32().unwrap_or_default(),
        ))
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server =
                match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}

fn cmd_serve_hidden(out: &Output, path: &Path, relay: &str, headless: bool) -> Result<()> {
    use keep_core::crypto::{self, EncryptedData};
    use keep_core::hidden::HiddenStorage;
    use keep_core::keyring::Keyring;

    debug!(relay, headless, "starting server from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    out.hidden_label();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        let decrypted = secret_bytes.as_slice()?;
        secret.copy_from_slice(&decrypted);
        keyring.load_key(record.pubkey, secret, record.key_type, record.name)?;
        secret.zeroize();
    }

    let keyring = Arc::new(Mutex::new(keyring));
    let rt = tokio::runtime::Runtime::new().unwrap();

    if headless {
        rt.block_on(async {
            let mut server = Server::new(keyring, relay, None).await?;
            info!(relay, bunker_url = %server.bunker_url(), "hidden server started");
            out.field("Bunker URL", &server.bunker_url());
            out.field("Relay", relay);
            out.newline();
            out.info("Listening...");
            server.run().await
        })?;
        return Ok(());
    }

    let (bunker_url, npub) = rt.block_on(async {
        let server = Server::new(keyring.clone(), relay, None).await?;
        Ok::<_, KeepError>((
            server.bunker_url(),
            server.pubkey().to_bech32().unwrap_or_default(),
        ))
    })?;

    info!(relay, npub = %npub, "starting TUI for hidden volume");

    let (mut tui, tui_tx) = crate::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server =
                match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                            crate::tui::LogEntry::new("system", "server error", false)
                                .with_detail(&e.to_string()),
                        ));
                        return;
                    }
                };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(crate::tui::TuiEvent::Log(
                    crate::tui::LogEntry::new("system", "server error", false)
                        .with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}

fn cmd_bitcoin(out: &Output, path: &Path, command: BitcoinCommands) -> Result<()> {
    match command {
        BitcoinCommands::Address {
            key,
            count,
            network,
        } => cmd_bitcoin_address(out, path, &key, count, &network),
        BitcoinCommands::Descriptor {
            key,
            account,
            network,
        } => cmd_bitcoin_descriptor(out, path, &key, account, &network),
        BitcoinCommands::Sign {
            key,
            psbt,
            output,
            network,
        } => cmd_bitcoin_sign(out, path, &key, &psbt, output.as_deref(), &network),
        BitcoinCommands::Analyze { psbt, network } => cmd_bitcoin_analyze(out, &psbt, &network),
    }
}

fn parse_network(s: &str) -> Result<keep_bitcoin::Network> {
    match s.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(keep_bitcoin::Network::Bitcoin),
        "testnet" => Ok(keep_bitcoin::Network::Testnet),
        "signet" => Ok(keep_bitcoin::Network::Signet),
        "regtest" => Ok(keep_bitcoin::Network::Regtest),
        _ => Err(KeepError::InvalidNetwork(format!(
            "'{}' (valid: mainnet, testnet, signet, regtest)",
            s
        ))),
    }
}

fn cmd_bitcoin_address(
    out: &Output,
    path: &Path,
    key_name: &str,
    count: u32,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(secret, net)
        .map_err(|e| KeepError::Other(e.to_string()))?;
    secret.zeroize();

    out.newline();
    out.header("Bitcoin Addresses (BIP-86 Taproot)");
    out.field("Key", key_name);
    out.field("Network", network);
    out.newline();

    for i in 0..count {
        let addr = signer
            .get_receive_address(i)
            .map_err(|e| KeepError::Other(e.to_string()))?;
        out.info(&format!("Index {}: {}", i, addr));
    }

    Ok(())
}

fn cmd_bitcoin_descriptor(
    out: &Output,
    path: &Path,
    key_name: &str,
    account: u32,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(secret, net)
        .map_err(|e| KeepError::Other(e.to_string()))?;
    secret.zeroize();

    let export = signer
        .export_descriptor(account)
        .map_err(|e| KeepError::Other(e.to_string()))?;

    out.newline();
    out.header("Output Descriptor (BIP-86)");
    out.field("Key", key_name);
    out.field("Account", &account.to_string());
    out.field("Network", network);
    out.field("Fingerprint", &export.fingerprint);
    out.newline();
    out.info("External descriptor (receive):");
    println!("{}", export.descriptor);
    out.newline();
    out.info("Internal descriptor (change):");
    let internal = export
        .internal_descriptor()
        .map_err(|e| KeepError::Other(e.to_string()))?;
    println!("{}", internal);

    Ok(())
}

fn cmd_bitcoin_sign(
    out: &Output,
    path: &Path,
    key_name: &str,
    psbt_path: &str,
    output_path: Option<&str>,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(secret, net)
        .map_err(|e| KeepError::Other(e.to_string()))?;
    secret.zeroize();

    let psbt_data = std::fs::read_to_string(psbt_path)
        .map_err(|e| KeepError::Other(format!("Failed to read PSBT: {}", e)))?;

    let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_data.trim())
        .map_err(|e| KeepError::Other(e.to_string()))?;

    let spinner = out.spinner("Signing PSBT...");
    let signed_count = signer
        .sign_psbt(&mut psbt)
        .map_err(|e| KeepError::Other(e.to_string()))?;
    spinner.finish();

    let signed_base64 = keep_bitcoin::psbt::serialize_psbt_base64(&psbt);

    if let Some(output) = output_path {
        std::fs::write(output, &signed_base64)
            .map_err(|e| KeepError::Other(format!("Failed to write output: {}", e)))?;
        out.newline();
        out.success(&format!("Signed {} input(s)", signed_count));
        out.field("Output", output);
    } else {
        out.newline();
        out.success(&format!("Signed {} input(s)", signed_count));
        out.newline();
        println!("{}", signed_base64);
    }

    Ok(())
}

fn cmd_bitcoin_analyze(out: &Output, psbt_path: &str, network: &str) -> Result<()> {
    let psbt_data = std::fs::read_to_string(psbt_path)
        .map_err(|e| KeepError::Other(format!("Failed to read PSBT: {}", e)))?;

    let psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_data.trim())
        .map_err(|e| KeepError::Other(e.to_string()))?;

    let net = parse_network(network)?;
    let dummy_secret = [1u8; 32];
    let signer = keep_bitcoin::BitcoinSigner::new(dummy_secret, net)
        .map_err(|e| KeepError::Other(e.to_string()))?;

    let analysis = signer
        .analyze_psbt(&psbt)
        .map_err(|e| KeepError::Other(e.to_string()))?;

    out.newline();
    out.header("PSBT Analysis");
    out.field("Inputs", &analysis.num_inputs.to_string());
    out.field("Outputs", &analysis.num_outputs.to_string());
    out.field(
        "Total Input",
        &format!("{} sats", analysis.total_input_sats),
    );
    out.field(
        "Total Output",
        &format!("{} sats", analysis.total_output_sats),
    );
    out.field("Fee", &format!("{} sats", analysis.fee_sats));
    out.newline();

    out.info("Outputs:");
    for output in &analysis.outputs {
        let addr = output.address.as_deref().unwrap_or("(unknown)");
        let change = if output.is_change { " (change)" } else { "" };
        out.info(&format!(
            "  {}: {} sats -> {}{}",
            output.index, output.amount_sats, addr, change
        ));
    }

    if !analysis.signable_inputs.is_empty() {
        out.newline();
        out.info(&format!("Signable inputs: {:?}", analysis.signable_inputs));
    }

    Ok(())
}

fn cmd_enclave(out: &Output, path: &Path, command: EnclaveCommands) -> Result<()> {
    match command {
        EnclaveCommands::Status { cid, local } => cmd_enclave_status(out, cid, local),
        EnclaveCommands::Verify {
            cid,
            pcr0,
            pcr1,
            pcr2,
            local,
        } => cmd_enclave_verify(
            out,
            cid,
            pcr0.as_deref(),
            pcr1.as_deref(),
            pcr2.as_deref(),
            local,
        ),
        EnclaveCommands::GenerateKey { name, cid, local } => {
            cmd_enclave_generate_key(out, &name, cid, local)
        }
        EnclaveCommands::Sign {
            key,
            message,
            cid,
            local,
        } => cmd_enclave_sign(out, &key, &message, cid, local),
        EnclaveCommands::ImportKey {
            name,
            from_vault,
            cid,
            local,
        } => cmd_enclave_import_key(out, path, &name, from_vault.as_deref(), cid, local),
    }
}

fn cmd_enclave_status(out: &Output, cid: u32, local: bool) -> Result<()> {
    out.newline();
    out.header("Enclave Status");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let request = keep_enclave_host::EnclaveRequest::GetAttestation { nonce };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::Attestation { .. } => {
                out.success("Mock enclave is running");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    out.field("Target CID", &cid.to_string());

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        match client.get_attestation(nonce) {
            Ok(_) => {
                out.success("Enclave is running and responding");
            }
            Err(e) => {
                out.error(&format!("Enclave not available: {}", e));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

fn cmd_enclave_verify(
    out: &Output,
    cid: u32,
    pcr0: Option<&str>,
    pcr1: Option<&str>,
    pcr2: Option<&str>,
    local: bool,
) -> Result<()> {
    out.newline();
    out.header("Enclave Attestation Verification");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let request = keep_enclave_host::EnclaveRequest::GetAttestation { nonce };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::Attestation { document } => {
                out.success("Mock attestation generated");
                out.field("Document size", &format!("{} bytes", document.len()));
                out.warn("Mock attestation - not cryptographically verified");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    out.field("Target CID", &cid.to_string());

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let spinner = out.spinner("Fetching attestation...");
        let attestation_doc = client
            .get_attestation(nonce)
            .map_err(|e| KeepError::Other(e.to_string()))?;
        spinner.finish();

        let expected_pcrs = if let (Some(p0), Some(p1), Some(p2)) = (pcr0, pcr1, pcr2) {
            Some(
                keep_enclave_host::ExpectedPcrs::from_hex(p0, p1, p2)
                    .map_err(|e| KeepError::Other(e.to_string()))?,
            )
        } else {
            None
        };

        let verifier = keep_enclave_host::AttestationVerifier::new(expected_pcrs);

        let spinner = out.spinner("Verifying attestation...");
        match verifier.verify(&attestation_doc, &nonce) {
            Ok(verified) => {
                spinner.finish();
                out.success("Attestation verified!");
                out.newline();

                for (pcr_idx, pcr_val) in &verified.pcrs {
                    out.field(&format!("PCR{}", pcr_idx), &hex::encode(pcr_val));
                }
            }
            Err(e) => {
                spinner.finish();
                out.error(&format!("Verification failed: {}", e));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pcr0, pcr1, pcr2);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

fn cmd_enclave_generate_key(out: &Output, name: &str, cid: u32, local: bool) -> Result<()> {
    out.newline();
    out.header("Generate Key in Enclave");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let request = keep_enclave_host::EnclaveRequest::GenerateKey {
            name: name.to_string(),
        };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::PublicKey {
                pubkey,
                name: key_name,
            } => {
                let pubkey_arr: [u8; 32] = match pubkey.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        out.error(&format!(
                            "Invalid pubkey length: expected 32, got {}",
                            pubkey.len()
                        ));
                        return Ok(());
                    }
                };
                let npub = keep_core::keys::bytes_to_npub(&pubkey_arr);
                out.success("Key generated in mock enclave!");
                out.field("Name", &key_name);
                out.key_field("Pubkey", &npub);
                out.warn("Mock key - persisted to /tmp for local testing");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let spinner = out.spinner("Generating key in enclave...");
        let pubkey = client
            .generate_key(name)
            .map_err(|e| KeepError::Other(e.to_string()))?;
        spinner.finish();

        let pubkey_arr: [u8; 32] = pubkey.as_slice().try_into().map_err(|_| {
            KeepError::Other(format!(
                "Invalid pubkey length: expected 32, got {}",
                pubkey.len()
            ))
        })?;
        let npub = keep_core::keys::bytes_to_npub(&pubkey_arr);

        out.success("Key generated in enclave!");
        out.field("Name", name);
        out.key_field("Pubkey", &npub);
        out.warn("Key exists ONLY in enclave memory");
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, cid);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

fn cmd_enclave_sign(out: &Output, key: &str, message: &str, cid: u32, local: bool) -> Result<()> {
    out.newline();
    out.header("Sign in Enclave");

    let message_bytes =
        hex::decode(message).map_err(|_| KeepError::Other("Invalid message hex".into()))?;

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let sign_request =
            keep_enclave_host::EnclaveRequest::Sign(keep_enclave_host::SigningRequest {
                key_id: key.to_string(),
                message: message_bytes,
                event_kind: None,
                amount_sats: None,
                destination: None,
                nonce: None,
                timestamp: None,
            });

        match client.process_request(sign_request) {
            keep_enclave_host::EnclaveResponse::Signature { signature } => {
                out.success("Signature generated in mock enclave!");
                out.newline();
                println!("{}", hex::encode(&signature));
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let request = keep_enclave_host::SigningRequest {
            key_id: key.to_string(),
            message: message_bytes,
            event_kind: None,
            amount_sats: None,
            destination: None,
            nonce: None,
            timestamp: None,
        };

        let spinner = out.spinner("Signing in enclave...");
        let signature = client
            .sign(request)
            .map_err(|e| KeepError::Other(e.to_string()))?;
        spinner.finish();

        out.success("Signature generated!");
        out.newline();
        println!("{}", hex::encode(signature));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (key, cid);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

fn cmd_enclave_import_key(
    out: &Output,
    path: &Path,
    name: &str,
    from_vault: Option<&str>,
    cid: u32,
    local: bool,
) -> Result<()> {
    out.newline();
    out.header("Import Key to Enclave");

    let mut secret = if let Some(vault_key) = from_vault {
        out.field("Source", &format!("vault key '{}'", vault_key));

        let mut keep = Keep::open(path)?;
        let password = get_password("Enter password")?;

        let spinner = out.spinner("Unlocking vault...");
        keep.unlock(password.expose_secret())?;
        spinner.finish();

        let slot = keep
            .keyring()
            .get_by_name(vault_key)
            .ok_or_else(|| KeepError::KeyNotFound(vault_key.into()))?;

        let keypair = slot.to_nostr_keypair()?;
        keypair.secret_bytes().to_vec()
    } else {
        out.field("Source", "stdin (hex)");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| KeepError::Other(format!("Read error: {}", e)))?;
        let decoded =
            hex::decode(input.trim()).map_err(|_| KeepError::Other("Invalid hex".into()))?;
        input.zeroize();
        decoded
    };

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let request = keep_enclave_host::EnclaveRequest::ImportKey {
            name: name.to_string(),
            secret: secret.clone(),
        };
        secret.zeroize();

        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::PublicKey { pubkey, .. } => {
                let npub = if pubkey.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&pubkey);
                    keep_core::keys::bytes_to_npub(&arr)
                } else {
                    hex::encode(&pubkey)
                };
                out.success("Key imported to mock enclave!");
                out.key_field("Pubkey", &npub);
                out.warn("Mock key - persisted to /tmp for local testing");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let spinner = out.spinner("Importing key to enclave...");
        let result = client.import_key(name, &secret);
        secret.zeroize();
        let pubkey = result.map_err(|e| KeepError::Other(e.to_string()))?;
        spinner.finish();

        let npub = if pubkey.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey);
            keep_core::keys::bytes_to_npub(&arr)
        } else {
            hex::encode(&pubkey)
        };
        out.success("Key imported to enclave!");
        out.key_field("Pubkey", &npub);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, cid);
        secret.zeroize();
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}
