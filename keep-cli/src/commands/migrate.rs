use std::path::Path;

use secrecy::ExposeSecret;
use tracing::info;

use keep_core::error::Result;
use keep_core::migration::CURRENT_SCHEMA_VERSION;
use keep_core::storage::Storage;

use crate::output::Output;

use super::get_password;

pub fn cmd_migrate(out: &Output, path: &Path) -> Result<()> {
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

pub fn cmd_migrate_status(out: &Output, path: &Path) -> Result<()> {
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
