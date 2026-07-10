// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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
    /// Create a new encrypted vault at the given path
    Init {
        #[arg(long, default_value = "100")]
        size: u64,
    },
    /// Generate a new Nostr keypair and store it in the vault
    Generate {
        #[arg(short, long, default_value = "default")]
        name: String,
        #[arg(
            long,
            help = "Allow generating a second key under an existing name. Default refuses so name-based operations stay unambiguous."
        )]
        force: bool,
    },
    /// Import an existing Nostr nsec into the vault
    Import {
        #[arg(short, long, default_value = "imported")]
        name: String,
        #[arg(
            long,
            help = "Allow importing under an existing name. Default refuses so name-based operations stay unambiguous."
        )]
        force: bool,
    },
    /// List keys stored in the vault
    List,
    /// Print a raw nsec for the named key. Interactive-only by design:
    /// refuses unless stdin and stderr are both a TTY and no automation env
    /// vars (KEEP_YES / KEEP_PASSWORD) are set (see #467 for policy rationale).
    Export {
        #[arg(short, long)]
        name: String,
    },
    /// Remove a key from the vault
    Delete {
        #[arg(short, long)]
        name: String,
    },
    /// Change the vault unlock password
    RotatePassword,
    /// Rotate the vault data-encryption key (re-encrypts every secret)
    RotateDataKey,
    /// Start the NIP-46 bunker (and optional FROST network co-signer)
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
    /// Inspect, verify, export, or prune the audit log
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// FROST threshold-signature operations (generate, sign, network coordination)
    Frost {
        #[command(subcommand)]
        command: FrostCommands,
    },
    /// Bitcoin address derivation, descriptor management, and PSBT signing
    Bitcoin {
        #[command(subcommand)]
        command: BitcoinCommands,
    },
    /// AWS Nitro Enclave operations (attest, generate, sign)
    Enclave {
        #[command(subcommand)]
        command: EnclaveCommands,
    },
    /// NIP-46 bunker app management: pre-grant, list, and revoke client permissions
    Nip46 {
        #[command(subcommand)]
        command: Nip46Commands,
    },
    /// Agent integrations (MCP server, etc.)
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// FROST wallet descriptors, proposals, and PSBT spend coordination
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Inspect or initialize the keep CLI config file
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Inspect or apply on-disk schema migrations
    Migrate {
        #[command(subcommand)]
        command: Option<MigrateCommands>,
    },
    /// Write a passphrase-encrypted backup of the vault to a file
    Backup {
        #[arg(short, long, help = "Output file path")]
        output: Option<PathBuf>,
    },
    /// Restore a backup file into a NEW vault at --target
    Restore {
        #[arg(help = "Backup file to restore from")]
        file: PathBuf,
        #[arg(
            long,
            help = "Target vault path. Required; no default to avoid restoring over the active ~/.keep vault."
        )]
        target: PathBuf,
    },
    /// Sign a file with a FROST-Ed25519 threshold group (minisign .sig)
    Sign {
        #[arg(help = "File to sign")]
        file: PathBuf,
        #[arg(short, long, help = "FROST-Ed25519 group npub or hex")]
        group: String,
        #[arg(short, long, help = "Output signature path (default: <file>.minisig)")]
        output: Option<PathBuf>,
        #[arg(short = 'c', long, help = "Untrusted comment line")]
        comment: Option<String>,
        #[arg(
            short = 't',
            long,
            help = "Trusted comment line (bound into the signature)"
        )]
        trusted_comment: Option<String>,
    },
    /// Verify a minisign detached signature over a file
    Verify {
        #[arg(help = "File that was signed")]
        file: PathBuf,
        #[arg(help = "Detached signature file (.minisig)")]
        sig: PathBuf,
        #[arg(
            short,
            long,
            help = "FROST-Ed25519 group npub/hex, or path to a minisign public key file"
        )]
        group: String,
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
pub(crate) enum Nip46Commands {
    /// List persisted NIP-46 client app permission grants
    Apps,
    /// Pre-grant a NIP-46 client app a set of permissions.
    ///
    /// Granted apps are stored in the global RelayConfig and loaded into the
    /// PermissionManager when `keep serve` starts. This is the headless
    /// alternative to approving via the desktop's interactive prompt.
    Grant {
        #[arg(help = "Client app's nostr pubkey (hex or npub)")]
        pubkey: String,
        #[arg(long, default_value = "unnamed", help = "Display name for the app")]
        name: String,
        #[arg(
            long,
            help = "Comma-separated permission names: get_public_key, sign_event, nip04_encrypt, nip04_decrypt, nip44_encrypt, nip44_decrypt. Pass 'all' to grant everything.",
            default_value = "get_public_key,sign_event"
        )]
        permissions: String,
        #[arg(
            long,
            help = "Comma-separated event kinds that skip per-event approval (e.g. '1,7,22242')",
            default_value = ""
        )]
        auto_approve_kinds: String,
        #[arg(
            long,
            help = "Grant duration: 'session' (until restart), 'forever', or a number of seconds (e.g. '3600').",
            default_value = "forever"
        )]
        duration: String,
    },
    /// Revoke a NIP-46 client app's permissions
    Revoke {
        #[arg(help = "Client app's nostr pubkey (hex or npub)")]
        pubkey: String,
    },
    /// Set the global list of event kinds auto-approved for every client.
    ///
    /// Independent of a grant's per-app `auto_approve_kinds`. Applies when
    /// serving with an interactive approval prompt; headless serving
    /// auto-approves every request regardless. Pass no kinds to clear.
    AutoApprove {
        #[arg(
            long,
            help = "Comma-separated event kinds to auto-approve (e.g. '1,7'). Empty clears the list.",
            default_value = ""
        )]
        kinds: String,
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
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default to prevent silent testnet outputs."
        )]
        network: String,
        #[arg(
            long,
            help = "Allow a single-chain descriptor where external (receive) and internal (change) collapse to the same address. Required because simple FROST-key descriptors have no BIP-32 derivation; addresses will be reused. Prefer `wallet propose` with a recovery tier for proper external/internal split."
        )]
        allow_address_reuse: bool,
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
    /// Register a stored wallet descriptor on a NIP-46 hardware signer
    Register {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(
            short,
            long,
            help = "NIP-46 bunker URI (bunker://<pubkey>?relay=...&secret=...)"
        )]
        device: String,
        #[arg(long, help = "Wallet display name sent to the signer")]
        name: Option<String>,
        #[arg(long, help = "Print the registration token (HMAC) to the terminal")]
        show_token: bool,
        #[arg(long, help = "Device kind label (e.g. Coldcard, Ledger, BitBox02)")]
        kind: Option<String>,
        #[arg(long, help = "BIP32 master key fingerprint, 8 hex chars")]
        fingerprint: Option<String>,
        #[arg(long, help = "Firmware version string reported by the signer")]
        firmware_version: Option<String>,
    },
    /// List hardware signers that have registered a stored wallet
    Registrations {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(long, help = "Print the registration tokens (HMACs) to the terminal")]
        show_token: bool,
    },
    /// Propose a wallet descriptor via Nostr descriptor coordination
    Propose {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default to prevent silent signet proposals."
        )]
        network: String,
        #[arg(short, long, help = "Nostr relay URL")]
        relay: Option<String>,
        #[arg(long, help = "Share index to use")]
        share: Option<u16>,
        #[arg(
            long,
            help = "Recovery tier, e.g. '2of3@6mo' (threshold-of-keys@timelock). Timelock units: mo/month/months or y/year/years; case-insensitive. Repeat for multiple tiers.",
            required = true
        )]
        recovery: Vec<String>,
        #[arg(long, help = "Session timeout in seconds (max 86400)")]
        timeout: Option<u64>,
        /// Required when a finalized descriptor already exists for this
        /// group. Refuses unless paired with --replacing-version <N>
        /// matching the stored version. Without this, the propose would
        /// silently overwrite the stored descriptor and break wallet
        /// address generation. See #426 for the policy rationale.
        #[arg(long, requires = "replacing_version")]
        force: bool,
        /// The version number of the existing descriptor this propose
        /// intends to replace. Must match what `wallet show` reports for
        /// the group. Belt-and-suspenders against muscle-memory --force.
        #[arg(long, requires = "force")]
        replacing_version: Option<u32>,
    },
    /// Propose a recovery-tier (scriptpath) spend via WDC PSBT coordination
    Spend {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(long, help = "Recovery tier index (0 = first recovery tier)")]
        recovery_tier: u32,
        #[arg(
            long,
            help = "Path to an unsigned PSBT file (binary or base64) describing the recovery spend"
        )]
        psbt_file: PathBuf,
        #[arg(long, help = "Fee in sats (for display)", default_value = "0")]
        fee: u64,
        #[arg(
            long,
            help = "Required number of partial signatures",
            default_value = "1"
        )]
        threshold: u32,
        #[arg(
            long,
            help = "Expected signer FROST share index (repeatable)",
            default_values_t = Vec::<u16>::new(),
        )]
        signer_share: Vec<u16>,
        #[arg(
            long,
            help = "Expected signer xpub fingerprint, 8 hex chars (repeatable)",
            default_values_t = Vec::<String>::new(),
        )]
        signer_fingerprint: Vec<String>,
        #[arg(long, help = "Share index to use for signing")]
        share: Option<u16>,
        #[arg(short, long, help = "Nostr relay URL")]
        relay: Option<String>,
        #[arg(long, help = "Session timeout in seconds (max 86400)")]
        timeout: Option<u64>,
    },
    /// Approve a pending recovery-tier PSBT proposal as an external signer
    /// holder (responder side). Resolves the locally-held NIP-46 signer for
    /// the matching xpub fingerprint, signs the tap script, merges the sig,
    /// and contributes it back to the initiator.
    ApprovePsbt {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(
            long,
            help = "PSBT session id to approve (hex, 64 chars).",
            required = true
        )]
        session: String,
        #[arg(
            long,
            help = "Local signer mapping 'fingerprint:bunker://...' (8 hex fp, colon, URI). Repeatable.",
            required = true
        )]
        signer_bunker: Vec<String>,
        #[arg(long, help = "Share index to use for participation")]
        share: Option<u16>,
        #[arg(short, long, help = "Nostr relay URL")]
        relay: Option<String>,
        #[arg(
            long,
            help = "Seconds to wait for a matching PsbtSignatureNeeded proposal before giving up. Default 20s; the old 60s was excessive when the initiator simply wasn't online or the session id was a typo. Upper bound is enforced by keep_frost_net::DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS.",
            default_value = "20"
        )]
        timeout: u32,
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
        #[arg(long, help = "Generate a FROST-Ed25519 group (for release signing)")]
        ed25519: bool,
        #[arg(
            long,
            help = "Write the minisign public key for the group to this path (Ed25519 only)"
        )]
        pubkey_out: Option<PathBuf>,
    },
    Split {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value = "2")]
        threshold: u16,
        #[arg(short, long, default_value = "3")]
        shares: u16,
        #[arg(
            long,
            help = "Retain the original single-key Nostr key after splitting (default: delete it so threshold security is actually in effect)"
        )]
        keep_original: bool,
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
    /// Delete a stored FROST share from the vault (audit-logged)
    DeleteShare {
        #[arg(short, long, help = "FROST group npub or hex")]
        group: String,
        #[arg(short, long, help = "Share identifier (1-indexed)")]
        share: u16,
    },
    /// Verify a BIP-340 Schnorr signature against a FROST group pubkey
    Verify {
        #[arg(short, long, help = "Message hex (the bytes that were signed)")]
        message: String,
        #[arg(short, long, help = "FROST group npub or hex pubkey")]
        group: String,
        #[arg(short, long, help = "64-byte schnorr signature as hex")]
        signature: String,
    },
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
        /// Refuse FROST sign requests labeled `message_type="raw"`.
        ///
        /// Without this, an authorized requester can have co-signers blind-sign
        /// any 32-byte digest framed as raw, including a Bitcoin taproot sighash.
        /// Recommended on groups that also coordinate a wallet descriptor.
        /// See #524 for the deeper protocol-level fix.
        #[arg(long)]
        refuse_raw_sign: bool,
        /// Refuse any sign request that does not carry a structured payload the
        /// co-signer can recompute the digest from (#529). Combined with
        /// --refuse-raw-sign this closes the cross-domain label spoof for hybrid
        /// Nostr + Bitcoin groups. Default off; enable once all peers attach
        /// structured payloads.
        #[arg(long)]
        require_structured_sign: bool,
        /// TOML file pinning each peer's TPM attestation key and the reference
        /// PCRs they must quote. The node verifies a peer's measured-boot state
        /// against this before answering its OPRF evaluation requests. Required
        /// unless `--insecure-no-attestation` is set.
        #[arg(long, value_name = "FILE")]
        attestation_config: Option<PathBuf>,
        /// Run without a peer-attestation policy (test/dev only). The OPRF
        /// oracle independently requires a `Verified` peer, so with no policy no
        /// peer is ever verified and the node serves NO OPRF evaluations; it
        /// still participates in FROST coordination. Mutually exclusive with
        /// `--attestation-config`.
        #[arg(long)]
        insecure_no_attestation: bool,
        /// Act as an OPRF holder: load this 64-byte OPRF key share at boot so the
        /// node answers evaluation requests, and seal a freshly enrolled share
        /// here. If the file is absent the node serves without a share until one
        /// is enrolled (see --oprf-dealer).
        #[arg(long, value_name = "FILE")]
        oprf_share_file: Option<PathBuf>,
        /// Pin the share index allowed to deal this node an OPRF enrollment. Set
        /// it to the box's index to accept a share only from the designated
        /// dealer; without it, enrollment is refused fail-closed.
        #[arg(long, value_name = "INDEX")]
        oprf_dealer: Option<u16>,
        /// Auto-answer OPRF evaluation requests instead of declining them (the
        /// default). Safe only because the oracle already requires the requester
        /// to have VERIFIED attestation and is rate-limited; this is the explicit
        /// opt-in for an autonomous holder (e.g. a replica) that must answer
        /// attested requests unattended. Leave off to gate each eval behind a human.
        #[arg(long)]
        oprf_auto_approve: bool,
        /// Attach a TPM quote to this node's announces (e.g. device:/dev/tpmrm0)
        /// so peers can verify it and a holder can pin it via
        /// `attestation-provision`. Needs the tpm-attestation build feature.
        #[arg(long, value_name = "TCTI")]
        tpm_tcti: Option<String>,
        /// Coercion resistance: the pinned duress-beacon npub from
        /// `duress-provision`. When set (with --duress-beacon-salt), entering the
        /// duress credential at the password prompt fails closed (the vault stays
        /// locked, no OPRF share is loaded, so the box drops below threshold) and
        /// publishes a signed duress beacon, indistinguishable from a normal start.
        #[arg(long, value_name = "NPUB", requires = "duress_beacon_salt")]
        duress_beacon_pubkey: Option<String>,
        /// Coercion resistance: the hex salt printed by `duress-provision`, used to
        /// re-derive and detect the duress credential. Set together with
        /// --duress-beacon-pubkey.
        #[arg(long, value_name = "HEX", requires = "duress_beacon_pubkey")]
        duress_beacon_salt: Option<String>,
        /// Coercion resistance: a group holder's duress-beacon npub to TRUST.
        /// Repeatable. Receiving a verified beacon signed by any pinned key freezes
        /// this node: it refuses co-signing and OPRF evaluations (fail-closed) until
        /// an out-of-band operator clear. These are OTHER holders' beacon pubkeys
        /// (from their `duress-provision`), distinct from this node's own
        /// --duress-beacon-pubkey trigger.
        #[arg(long = "duress-beacon-pin", value_name = "NPUB")]
        duress_beacon_pins: Vec<String>,
        /// Coercion resistance: file that makes a duress freeze STICKY across
        /// reboot. On a freeze the state is written here; at startup an existing
        /// file re-freezes the node before it serves, so a restart cannot silently
        /// resume answering. Only an out-of-band operator clear (removing/clearing
        /// this file) lifts the freeze.
        #[arg(long, value_name = "FILE")]
        duress_state_file: Option<PathBuf>,
    },
    Peers {
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        relay: Option<String>,
    },
    /// Provision a duress credential: derive and print the duress-beacon pubkey
    /// (to pin with the cluster) and salt (to configure on `serve`). The
    /// credential is never stored. Coercion resistance (inc1b).
    DuressProvision,
    /// Author an attestation-config from observed announces (trust-on-first-use).
    AttestationProvision {
        #[arg(short, long, help = "FROST group npub")]
        group: String,
        #[arg(short, long, help = "Coordination relay URL")]
        relay: Option<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Write the attestation policy TOML here"
        )]
        out: PathBuf,
        #[arg(
            long,
            default_value = "25",
            help = "Seconds to listen for announces (>= one announce interval)"
        )]
        wait: u64,
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
        #[arg(
            long,
            help = "Hardware signer device path (e.g., /dev/ttyACM0). \
                    Omit to run software DKG in-process, storing the resulting \
                    share in the vault (#454)."
        )]
        hardware: Option<String>,
        #[arg(
            long,
            help = "Vault path override for software DKG. Defaults to the global \
                    --path / configured vault; the finalized share is stored here \
                    encrypted under the vault key."
        )]
        path: Option<std::path::PathBuf>,
        #[arg(
            long,
            help = "Name of a vault-stored identity key to sign DKG events with \
                    (#674). Must be the same npub that appears at --index in the \
                    signed kind-21101 group announcement. Defaults to the vault's \
                    primary key."
        )]
        identity: Option<String>,
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
    /// Build a Nostr event with the FROST group pubkey as the author,
    /// FROST-sign its canonical event id across peers, and emit the signed
    /// event as JSON.
    SignEvent {
        #[arg(short, long, help = "FROST group npub (event author)")]
        group: String,
        #[arg(short, long, help = "Nostr event kind")]
        kind: u16,
        #[arg(short, long, help = "Event content")]
        content: String,
        #[arg(short, long, help = "Coordination relay URL")]
        relay: Option<String>,
        #[arg(short, long, help = "Local share index to use")]
        share: Option<u16>,
        #[arg(
            long,
            help = "Hardware signer device path (not yet supported for sign-event, see follow-up)"
        )]
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
    /// Reconstruct a LUKS key from a 2-of-3 threshold-OPRF quorum and write the
    /// 32 raw key bytes to STDOUT (pipe to `cryptsetup open --key-file -`).
    /// All progress/log output goes to STDERR; the key is the only thing on STDOUT.
    OprfUnlock {
        #[arg(short, long, help = "FROST group npub")]
        group: String,
        #[arg(short, long, help = "Coordination relay URL")]
        relay: Option<String>,
        #[arg(short, long, help = "Local FROST share index to use")]
        share: Option<u16>,
        #[arg(long, help = "LUKS volume identifier")]
        volume_id: String,
        #[arg(long, default_value = "1", help = "OPRF key epoch")]
        epoch: u32,
        #[arg(
            long,
            help = "Path to this box's 64-byte OPRF key share (TPM-unsealed at boot)"
        )]
        share_file: PathBuf,
        #[arg(
            long,
            value_name = "TCTI",
            help = "Attest this box's measured boot to holders by attaching a TPM quote to its \
                    announces. TCTI of the TPM (e.g. device:/dev/tpmrm0). Requires the \
                    tpm-attestation build feature."
        )]
        tpm_tcti: Option<String>,
    },
    /// One-time setup: act as the trusted dealer, generate the OPRF key, split
    /// it, distribute the remote shares to online holders, and write the LUKS
    /// key and this box's own OPRF share to 0600 files.
    OprfProvision {
        #[arg(short, long, help = "FROST group npub")]
        group: String,
        #[arg(short, long, help = "Coordination relay URL")]
        relay: Option<String>,
        #[arg(short, long, help = "Local FROST share index to use")]
        share: Option<u16>,
        #[arg(long, help = "LUKS volume identifier")]
        volume_id: String,
        #[arg(long, default_value = "1", help = "OPRF key epoch")]
        epoch: u32,
        #[arg(
            short,
            long,
            default_value = "2",
            help = "OPRF unlock threshold (t in t-of-n)"
        )]
        threshold: u16,
        #[arg(short = 'n', long, default_value = "3", help = "Total OPRF holders")]
        total: u16,
        #[arg(long, help = "Write the 32-byte LUKS key here (mode 0600)")]
        key_out: PathBuf,
        #[arg(
            long,
            help = "Write this box's own 64-byte OPRF share here (mode 0600)"
        )]
        share_out: PathBuf,
        #[arg(
            long,
            required = true,
            value_name = "TCTI",
            help = "Attest this box to the holders by attaching a TPM quote to its announces \
                    (e.g. device:/dev/tpmrm0). Required: holders refuse a share from an \
                    unattested dealer. Needs the tpm-attestation build feature."
        )]
        tpm_tcti: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FrostHardwareCommands {
    Ping {
        #[arg(short, long)]
        device: String,
    },
    /// Probe attached devices and report which are keep hardware signers
    List {
        #[arg(
            short,
            long,
            help = "Probe a specific device path. If omitted, scan /dev/ttyACM*, /dev/ttyUSB*, /dev/cu.usbmodem*."
        )]
        device: Option<String>,
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
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default to prevent silent testnet outputs (fund-loss risk if treated as mainnet)."
        )]
        network: String,
    },
    Descriptor {
        #[arg(short, long)]
        key: String,
        #[arg(long, default_value = "0")]
        account: u32,
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default."
        )]
        network: String,
    },
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(long)]
        psbt: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default."
        )]
        network: String,
    },
    Analyze {
        #[arg(short, long)]
        psbt: String,
        #[arg(
            long,
            help = "Bitcoin network: mainnet, testnet, signet, regtest. Required; no default."
        )]
        network: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn bitcoin_sign_short_p_is_global_path_not_psbt() {
        let cli = Cli::try_parse_from([
            "keep",
            "-p",
            "/tmp/vault",
            "bitcoin",
            "sign",
            "--key",
            "main",
            "--psbt",
            "/tmp/unsigned.psbt",
            "--network",
            "mainnet",
        ])
        .expect("parse bitcoin sign args");

        assert_eq!(cli.path, Some(PathBuf::from("/tmp/vault")));

        let Commands::Bitcoin { command } = cli.command else {
            panic!("expected bitcoin command");
        };
        let BitcoinCommands::Sign { psbt, .. } = command else {
            panic!("expected bitcoin sign command");
        };
        assert_eq!(psbt, "/tmp/unsigned.psbt");
    }

    #[test]
    fn bitcoin_sign_help_does_not_show_short_psbt_flag() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("bitcoin")
            .expect("bitcoin subcommand")
            .find_subcommand_mut("sign")
            .expect("sign subcommand")
            .render_help()
            .to_string();

        assert!(help.contains("--psbt <PSBT>"));
        assert!(!help.contains("-p, --psbt"));
    }
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
        #[arg(
            long,
            help = "INSECURE: skip PCR matching (cert-chain + nonce still verified). \
                    Dev/testing only; does NOT bind the attestation to a known image (#577)."
        )]
        insecure_no_pcrs: bool,
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
