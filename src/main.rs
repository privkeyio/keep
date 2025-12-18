use std::path::PathBuf;

use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use indicatif::{ProgressBar, ProgressStyle};
use tracing_subscriber::EnvFilter;

use keep::error::Result;
use keep::keys::bytes_to_npub;
use keep::{default_keep_path, Keep};

fn get_password(prompt: &str) -> String {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        return pw;
    }
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .unwrap()
}

fn get_password_confirm() -> String {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        return pw;
    }
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()
        .unwrap()
}

fn get_confirm(prompt: &str) -> bool {
    if std::env::var("KEEP_YES").is_ok() {
        return true;
    }
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap()
}

#[derive(Parser)]
#[command(name = "keep")]
#[command(about = "Sovereign key management for Nostr and Bitcoin")]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
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
        #[arg(short, long, default_value = "wss://relay.damus.io")]
        relay: String,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    if let Err(e) = run() {
        eprintln!("{} {}", style("Error:").red().bold(), e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.path.unwrap_or_else(default_keep_path);

    match cli.command {
        Commands::Init => cmd_init(&path),
        Commands::Generate { name } => cmd_generate(&path, &name),
        Commands::Import { name } => cmd_import(&path, &name),
        Commands::List => cmd_list(&path),
        Commands::Export { name } => cmd_export(&path, &name),
        Commands::Delete { name } => cmd_delete(&path, &name),
        Commands::Serve { relay } => cmd_serve(&path, &relay),
    }
}

fn cmd_init(path: &PathBuf) -> Result<()> {
    println!("{}", style("Creating new Keep...").cyan());
    println!("Path: {}\n", path.display());

    let password = get_password_confirm();

    if password.len() < 8 {
        return Err(keep::error::KeepError::Other(
            "Password must be at least 8 characters".into(),
        ));
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message("Deriving keys...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let _keep = Keep::create(path, &password)?;

    pb.finish_and_clear();

    println!("\n{} Keep created successfully!", style("✓").green().bold());
    println!("\nNext steps:");
    println!("  {} Generate a key", style("keep generate --name main").cyan());
    println!(
        "  {} Import existing key",
        style("keep import --name backup").cyan()
    );

    Ok(())
}

fn cmd_generate(path: &PathBuf, name: &str) -> Result<()> {
    let mut keep = Keep::open(path)?;

    let password = get_password("Enter password");

    keep.unlock(&password)?;

    let pubkey = keep.generate_key(name)?;
    let npub = bytes_to_npub(&pubkey);

    println!("\n{} Generated new key!", style("✓").green().bold());
    println!("  Name: {}", style(name).cyan());
    println!("  Pubkey: {}", style(&npub).yellow());

    Ok(())
}

fn cmd_import(path: &PathBuf, name: &str) -> Result<()> {
    let mut keep = Keep::open(path)?;

    let password = get_password("Enter password");

    keep.unlock(&password)?;

    let nsec = get_password("Enter nsec");

    let pubkey = keep.import_nsec(&nsec, name)?;
    let npub = bytes_to_npub(&pubkey);

    println!("\n{} Imported key!", style("✓").green().bold());
    println!("  Name: {}", style(name).cyan());
    println!("  Pubkey: {}", style(&npub).yellow());

    Ok(())
}

fn cmd_list(path: &PathBuf) -> Result<()> {
    let mut keep = Keep::open(path)?;

    let password = get_password("Enter password");

    keep.unlock(&password)?;

    let keys = keep.list_keys()?;

    if keys.is_empty() {
        println!(
            "\nNo keys found. Use {} to create one.",
            style("keep generate").cyan()
        );
        return Ok(());
    }

    println!(
        "\n{:<20} {:<20} {}",
        style("NAME").bold(),
        style("TYPE").bold(),
        style("PUBKEY").bold()
    );
    println!("{}", "─".repeat(70));

    for key in &keys {
        let npub = key.npub().unwrap_or_else(|| hex::encode(&key.pubkey[..8]));
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };

        println!(
            "{:<20} {:<20} {}",
            key.name,
            format!("{:?}", key.key_type),
            style(display_npub).yellow()
        );
    }

    println!("\n{} key(s) total", keys.len());

    Ok(())
}

fn cmd_export(path: &PathBuf, name: &str) -> Result<()> {
    let mut keep = Keep::open(path)?;

    let password = get_password("Enter password");

    keep.unlock(&password)?;

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| keep::error::KeepError::KeyNotFound(name.into()))?;

    let keypair = slot.to_nostr_keypair()?;

    println!(
        "\n{}",
        style("WARNING: Never share your private key!").red().bold()
    );
    println!();

    if get_confirm("Display nsec?") {
        println!("\n{}", keypair.to_nsec());
    }

    Ok(())
}

fn cmd_delete(path: &PathBuf, name: &str) -> Result<()> {
    let mut keep = Keep::open(path)?;

    let password = get_password("Enter password");

    keep.unlock(&password)?;

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| keep::error::KeepError::KeyNotFound(name.into()))?;

    let pubkey = slot.pubkey;

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name)) {
        println!("Cancelled.");
        return Ok(());
    }

    keep.delete_key(&pubkey)?;

    println!("\n{} Deleted key: {}", style("✓").green().bold(), name);

    Ok(())
}

fn cmd_serve(_path: &PathBuf, _relay: &str) -> Result<()> {
    println!("{}", style("NIP-46 signer not implemented yet.").yellow());
    println!("Coming in Phase 2!");
    Ok(())
}
