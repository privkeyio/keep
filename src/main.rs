use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use nostr_sdk::prelude::ToBech32;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

use keep::error::{KeepError, Result};
use keep::keys::bytes_to_npub;
use keep::output::Output;
use keep::server::Server;
use keep::{default_keep_path, Keep};

fn get_password(prompt: &str) -> String {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        debug!("using password from KEEP_PASSWORD env var");
        return pw;
    }
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .unwrap()
}

fn get_password_with_confirm(prompt: &str, confirm: &str) -> String {
    if let Ok(pw) = std::env::var("KEEP_PASSWORD") {
        debug!("using password from KEEP_PASSWORD env var");
        return pw;
    }
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .with_confirmation(confirm, "Passwords don't match")
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
        #[arg(short, long, default_value = "wss://relay.damus.io")]
        relay: String,
        #[arg(long)]
        headless: bool,
    },
}

fn main() {
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
    let path = cli.path.unwrap_or_else(default_keep_path);
    let hidden = cli.hidden;

    debug!(path = %path.display(), hidden, "starting command");

    match cli.command {
        Commands::Init { size } => cmd_init(out, &path, hidden, size),
        Commands::Generate { name } => cmd_generate(out, &path, &name, hidden),
        Commands::Import { name } => cmd_import(out, &path, &name, hidden),
        Commands::List => cmd_list(out, &path, hidden),
        Commands::Export { name } => cmd_export(out, &path, &name, hidden),
        Commands::Delete { name } => cmd_delete(out, &path, &name, hidden),
        Commands::Serve { relay, headless } => cmd_serve(out, &path, &relay, headless, hidden),
    }
}

fn cmd_init(out: &Output, path: &PathBuf, hidden: bool, size_mb: u64) -> Result<()> {
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

    let outer_password = get_password_with_confirm(outer_prompt, outer_confirm);

    if outer_password.len() < 8 {
        return Err(KeepError::Other("Password must be at least 8 characters".into()));
    }

    let hidden_password = if hidden {
        out.newline();
        let hp = if let Ok(hp_env) = std::env::var("KEEP_HIDDEN_PASSWORD") {
            debug!("using hidden password from KEEP_HIDDEN_PASSWORD env var");
            hp_env
        } else {
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter HIDDEN password (must be different!)")
                .with_confirmation("Confirm HIDDEN password", "Passwords don't match")
                .interact()
                .unwrap()
        };

        if hp == outer_password {
            return Err(KeepError::Other(
                "HIDDEN password must be DIFFERENT from OUTER password!".into(),
            ));
        }

        if hp.len() < 8 {
            return Err(KeepError::Other("Password must be at least 8 characters".into()));
        }

        Some(hp)
    } else {
        None
    };

    let spinner = out.spinner("Deriving keys and creating volume...");
    let total_size = size_mb * 1024 * 1024;

    info!(size_mb, hidden, "creating keep");

    if hidden {
        keep::hidden::HiddenStorage::create(
            path,
            &outer_password,
            hidden_password.as_deref(),
            total_size,
            0.2,
        )?;
    } else {
        Keep::create(path, &outer_password)?;
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

fn cmd_generate(out: &Output, path: &PathBuf, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_generate_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_generate_outer(out, path, name);
    }

    debug!(name, "generating key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
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

fn cmd_generate_outer(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;
    use keep::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());
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

fn cmd_generate_hidden(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;
    use keep::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "generating key in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
    spinner.finish();

    let spinner = out.spinner("Generating key...");
    let keypair = NostrKeypair::generate();
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());
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

fn cmd_import(out: &Output, path: &PathBuf, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_import_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_import_outer(out, path, name);
    }

    debug!(name, "importing key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
    spinner.finish();

    let nsec = get_password("Enter nsec");

    let spinner = out.spinner("Importing key...");
    let pubkey = keep.import_nsec(&nsec, name)?;
    spinner.finish();

    let npub = bytes_to_npub(&pubkey);
    info!(name, npub = %npub, "key imported");

    out.newline();
    out.success("Imported key!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);

    Ok(())
}

fn cmd_import_outer(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;
    use keep::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
    spinner.finish();

    let nsec = get_password("Enter nsec");

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(&nsec)?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());
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

fn cmd_import_hidden(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;
    use keep::keys::{KeyRecord, KeyType, NostrKeypair};

    debug!(name, "importing key to hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
    spinner.finish();

    let nsec = get_password("Enter nsec");

    let spinner = out.spinner("Importing key...");
    let keypair = NostrKeypair::from_nsec(&nsec)?;
    let pubkey = *keypair.public_bytes();
    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let encrypted = crypto::encrypt(keypair.secret_bytes(), data_key)?;
    let record = KeyRecord::new(pubkey, KeyType::Nostr, name.to_string(), encrypted.to_bytes());
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

fn cmd_list(out: &Output, path: &PathBuf, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_list_hidden(out, path);
    }
    if is_hidden_vault(path) {
        return cmd_list_outer(out, path);
    }

    debug!("listing keys");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
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

fn cmd_list_outer(out: &Output, path: &PathBuf) -> Result<()> {
    use keep::hidden::HiddenStorage;

    debug!("listing keys in outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
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

fn cmd_list_hidden(out: &Output, path: &PathBuf) -> Result<()> {
    use keep::hidden::HiddenStorage;

    debug!("listing keys in hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
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

fn cmd_export(out: &Output, path: &PathBuf, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_export_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_export_outer(out, path, name);
    }

    debug!(name, "exporting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let keypair = slot.to_nostr_keypair()?;

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?") {
        warn!(name, "nsec exported");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_outer(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto::{self, EncryptedData};
    use keep::hidden::HiddenStorage;
    use keep::keys::NostrKeypair;

    debug!(name, "exporting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
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
    secret.copy_from_slice(secret_bytes.as_slice());
    let keypair = NostrKeypair::from_secret_bytes(&secret)?;
    secret.zeroize();

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?") {
        warn!(name, "nsec exported from outer volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_export_hidden(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto::{self, EncryptedData};
    use keep::hidden::HiddenStorage;
    use keep::keys::NostrKeypair;

    debug!(name, "exporting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
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
    secret.copy_from_slice(secret_bytes.as_slice());
    let keypair = NostrKeypair::from_secret_bytes(&secret)?;
    secret.zeroize();

    out.secret_warning();
    out.newline();

    if get_confirm("Display nsec?") {
        warn!(name, "nsec exported from hidden volume");
        out.newline();
        out.info(&keypair.to_nsec());
    }

    Ok(())
}

fn cmd_delete(out: &Output, path: &PathBuf, name: &str, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_delete_hidden(out, path, name);
    }
    if is_hidden_vault(path) {
        return cmd_delete_outer(out, path, name);
    }

    debug!(name, "deleting key");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let pubkey = slot.pubkey;

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name)) {
        out.info("Cancelled.");
        return Ok(());
    }

    keep.delete_key(&pubkey)?;
    info!(name, "key deleted");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_outer(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;

    debug!(name, "deleting key from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
    spinner.finish();

    let keys = storage.list_keys()?;
    let record = keys
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| KeepError::KeyNotFound(name.into()))?;

    let id = crypto::blake2b_256(&record.pubkey);

    if !get_confirm(&format!("Delete key '{}'? This cannot be undone!", name)) {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from outer volume");

    out.newline();
    out.success(&format!("Deleted key: {}", name));

    Ok(())
}

fn cmd_delete_hidden(out: &Output, path: &PathBuf, name: &str) -> Result<()> {
    use keep::crypto;
    use keep::hidden::HiddenStorage;

    debug!(name, "deleting key from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
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
    )) {
        out.info("Cancelled.");
        return Ok(());
    }

    storage.delete_key(&id)?;
    info!(name, "key deleted from hidden volume");

    out.newline();
    out.success(&format!("Deleted key from hidden volume: {}", name));

    Ok(())
}

fn cmd_serve(out: &Output, path: &PathBuf, relay: &str, headless: bool, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_serve_hidden(out, path, relay, headless);
    }
    if is_hidden_vault(path) {
        return cmd_serve_outer(out, path, relay, headless);
    }

    debug!(relay, headless, "starting server");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(&password)?;
    spinner.finish();

    let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
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
        Ok::<_, KeepError>((server.bunker_url(), server.pubkey().to_bech32().unwrap_or_default()))
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = keep::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server = match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                        keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                    ));
                    return;
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                    keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}

fn cmd_serve_outer(out: &Output, path: &PathBuf, relay: &str, headless: bool) -> Result<()> {
    use keep::crypto::{self, EncryptedData};
    use keep::hidden::HiddenStorage;
    use keep::keyring::Keyring;

    debug!(relay, headless, "starting server from outer volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter password");

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock_outer(&password)?;
    spinner.finish();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(secret_bytes.as_slice());
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
        Ok::<_, KeepError>((server.bunker_url(), server.pubkey().to_bech32().unwrap_or_default()))
    })?;

    info!(relay, npub = %npub, "starting TUI");

    let (mut tui, tui_tx) = keep::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server = match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                        keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                    ));
                    return;
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                    keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}

fn cmd_serve_hidden(out: &Output, path: &PathBuf, relay: &str, headless: bool) -> Result<()> {
    use keep::crypto::{self, EncryptedData};
    use keep::hidden::HiddenStorage;
    use keep::keyring::Keyring;

    debug!(relay, headless, "starting server from hidden volume");

    let mut storage = HiddenStorage::open(path)?;
    let password = get_password("Enter HIDDEN password");

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(&password)?;
    spinner.finish();

    out.hidden_label();

    let data_key = storage.data_key().ok_or(KeepError::Locked)?;
    let records = storage.list_keys()?;

    let mut keyring = Keyring::new();
    for record in records {
        let encrypted = EncryptedData::from_bytes(&record.encrypted_secret)?;
        let secret_bytes = crypto::decrypt(&encrypted, data_key)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(secret_bytes.as_slice());
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
        Ok::<_, KeepError>((server.bunker_url(), server.pubkey().to_bech32().unwrap_or_default()))
    })?;

    info!(relay, npub = %npub, "starting TUI for hidden volume");

    let (mut tui, tui_tx) = keep::tui::Tui::new(bunker_url, npub, relay.to_string());
    let tui_tx_clone = tui_tx.clone();
    let relay_clone = relay.to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut server = match Server::new(keyring, &relay_clone, Some(tui_tx_clone.clone())).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                        keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                    ));
                    return;
                }
            };

            if let Err(e) = server.run().await {
                let _ = tui_tx_clone.send(keep::tui::TuiEvent::Log(
                    keep::tui::LogEntry::new("system", "server error", false).with_detail(&e.to_string()),
                ));
            }
        });
    });

    tui.run().map_err(|e| KeepError::Other(e.to_string()))?;
    Ok(())
}
