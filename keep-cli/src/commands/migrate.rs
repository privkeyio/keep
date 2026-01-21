use std::path::Path;

use secrecy::ExposeSecret;
use tracing::info;

use keep_core::error::Result;
use keep_core::migration::CURRENT_SCHEMA_VERSION;
use keep_core::storage::Storage;

use crate::output::Output;

use super::{get_hidden_password, get_password};

pub fn cmd_migrate(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_migrate_hidden(out, path);
    }

    out.header("Database Migration");
    out.field("Path", &path.display().to_string());
    out.newline();

    let mut storage = Storage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock(password.expose_secret())?;
    spinner.finish();

    let version = storage.schema_version()?;
    out.field("Current version", &version.to_string());
    out.field("Target version", &CURRENT_SCHEMA_VERSION.to_string());
    out.newline();

    if !storage.needs_migration()? {
        out.success("Schema is up to date.");
        return Ok(());
    }

    let spinner = out.spinner("Running migrations...");
    let result = storage.run_migrations()?;
    spinner.finish();

    info!(
        from = result.from_version,
        to = result.to_version,
        count = result.migrations_run,
        "migrations completed"
    );

    out.newline();
    out.success(&format!(
        "Migrated from v{} to v{} ({} migrations)",
        result.from_version, result.to_version, result.migrations_run
    ));

    Ok(())
}

fn cmd_migrate_hidden(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    out.header("Database Migration (Hidden Volume)");
    out.field("Path", &path.display().to_string());
    out.newline();

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    out.success(
        "Hidden volumes use a different storage architecture and do not require schema migrations.",
    );

    Ok(())
}

pub fn cmd_migrate_status(out: &Output, path: &Path, hidden: bool) -> Result<()> {
    if hidden {
        return cmd_migrate_status_hidden(out, path);
    }

    out.header("Schema Status");
    out.field("Path", &path.display().to_string());
    out.newline();

    let mut storage = Storage::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    storage.unlock(password.expose_secret())?;
    spinner.finish();

    let version = storage.schema_version()?;
    let needs_migration = storage.needs_migration()?;

    out.field("Schema version", &version.to_string());
    out.field("Latest version", &CURRENT_SCHEMA_VERSION.to_string());
    out.field("Needs migration", &needs_migration.to_string());

    Ok(())
}

fn cmd_migrate_status_hidden(out: &Output, path: &Path) -> Result<()> {
    use keep_core::hidden::HiddenStorage;

    out.header("Schema Status (Hidden Volume)");
    out.field("Path", &path.display().to_string());
    out.newline();

    let mut storage = HiddenStorage::open(path)?;
    let password = get_hidden_password("Enter HIDDEN password")?;

    let spinner = out.spinner("Unlocking hidden volume...");
    storage.unlock_hidden(password.expose_secret())?;
    spinner.finish();

    out.field("Storage type", "Hidden volume (file-based)");
    out.field("Needs migration", "false");
    out.newline();
    out.info(
        "Hidden volumes use a different storage architecture and do not require schema migrations.",
    );

    Ok(())
}
