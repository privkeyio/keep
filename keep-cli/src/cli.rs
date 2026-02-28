// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "keep")]
#[command(about = "Sovereign key management for Nostr and Bitcoin")]
#[command(version)]
pub(crate) struct Cli {
    #[arg(short, long, global = true)]
    pub path: Option<PathBuf>,

    #[arg(long, global = true)]
    pub hidden: bool,

    #[arg(
        long,
        global = true,
        help = "Disable memory locking (accepts degraded security)"
    )]
    pub no_mlock: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
    RotatePassword,
    RotateDataKey,
    Serve {
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(long)]
        headless: bool,
        #[arg(long)]
        frost_group: Option<String>,
        #[arg(long)]
        frost_relay: Option<String>,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
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
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Migrate {
        #[command(subcommand)]
        command: Option<MigrateCommands>,
    },
    Backup {
        #[arg(short, long, help = "Output file path")]
        output: Option<PathBuf>,
    },
    Restore {
        #[arg(help = "Backup file to restore from")]
        file: PathBuf,
        #[arg(long, help = "Target vault path")]
        target: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum MigrateCommands {
    Status,
}

#[derive(Subcommand)]
pub(crate) enum AgentCommands {
    Mcp {
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuditCommands {
    List {
        #[arg(short, long, help = "Number of entries to show")]
        limit: Option<usize>,
    },
    Export {
        #[arg(short, long, help = "Output file path")]
        output: Option<String>,
    },
    Verify,
    Retention {
        #[arg(long, help = "Maximum entries to keep")]
        max_entries: Option<usize>,
        #[arg(long, help = "Maximum age in days")]
        max_days: Option<u32>,
        #[arg(long, help = "Apply retention policy now")]
        apply: bool,
    },
    Stats,
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    Show,
    Path,
    Init,
}

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum ExportFormat {
    Json,
    Bech32,
}

#[derive(Subcommand)]
pub(crate) enum WalletCommands {
    /// List stored wallet descriptors
    List,
    /// Show descriptor for a specific FROST group
    Show {
        #[arg(short, long)]
        group: String,
    },
    /// Export descriptor in various formats
    Export {
        #[arg(short, long)]
        group: String,
        #[arg(long, default_value = "plain")]
        format: WalletExportFormat,
    },
    /// Create a simple descriptor from a FROST group (no recovery tiers)
    Descriptor {
        #[arg(short, long, help = "FROST group pubkey hex")]
        group: String,
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    /// Delete a stored wallet descriptor
    Delete {
        #[arg(short, long)]
        group: String,
    },
    /// Announce recovery xpubs to FROST group peers
    AnnounceKeys {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(short, long, help = "Nostr relay URL")]
        relay: Option<String>,
        #[arg(long, help = "Share index to use")]
        share: Option<u16>,
        #[arg(
            long,
            help = "Recovery xpub: 'xpub.../fingerprint' or 'xpub.../fingerprint/label'",
            required = true
        )]
        xpub: Vec<String>,
    },
    /// Propose a wallet descriptor via Nostr descriptor coordination
    Propose {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(long, default_value = "signet")]
        network: String,
        #[arg(short, long, help = "Nostr relay URL")]
        relay: Option<String>,
        #[arg(long, help = "Share index to use")]
        share: Option<u16>,
        #[arg(
            long,
            help = "Recovery tier, e.g. '2of3@6mo' (threshold-of-keys@timelock). Repeat for multiple tiers.",
            required = true
        )]
        recovery: Vec<String>,
        #[arg(long, help = "Session timeout in seconds (max 86400)")]
        timeout: Option<u64>,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum WalletExportFormat {
    Plain,
    Sparrow,
}

#[derive(Subcommand)]
pub(crate) enum FrostCommands {
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
        #[arg(short, long, default_value = "bech32")]
        format: ExportFormat,
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
    Refresh {
        #[arg(short, long)]
        group: String,
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
pub(crate) enum FrostNetworkCommands {
    Serve {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, help = "Automatically contribute xpub to descriptor proposals")]
        auto_contribute_descriptor: bool,
    },
    Peers {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        relay: Option<String>,
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
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyACM0)")]
        hardware: String,
    },
    Sign {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        message: String,
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyACM0)")]
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
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, help = "Hardware signer device path (e.g., /dev/ttyACM0)")]
        hardware: Option<String>,
    },
    GroupCreate {
        #[arg(long, help = "Group name/identifier")]
        name: String,
        #[arg(short, long, help = "Signature threshold (t in t-of-n)")]
        threshold: u8,
        #[arg(short = 'n', long, help = "Total participants")]
        participants: u8,
        #[arg(short, long, help = "Relay URLs (can specify multiple)")]
        relay: Vec<String>,
        #[arg(long, help = "Participant npubs (can specify multiple)")]
        participant_npub: Vec<String>,
    },
    NoncePrecommit {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        relay: Option<String>,
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
    HealthCheck {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        relay: Option<String>,
        #[arg(short, long)]
        share: Option<u16>,
        #[arg(long, default_value = "10", help = "Timeout in seconds")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub(crate) enum FrostHardwareCommands {
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
    Export {
        #[arg(short, long)]
        device: String,
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum BitcoinCommands {
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
pub(crate) enum EnclaveCommands {
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
