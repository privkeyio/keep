//! Database schema versioning and migrations.
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, info};

use crate::error::{KeepError, Result};

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

const SCHEMA_VERSION_KEY: &str = "schema_version";

/// The current schema version supported by this build.
pub const CURRENT_SCHEMA_VERSION: u32 = 6;

/// A migration function that transforms the database schema.
pub type MigrationFn = fn(&Database) -> Result<()>;

/// A single migration step.
pub struct Migration {
    /// The version this migration upgrades from.
    pub from_version: u32,
    /// The version this migration upgrades to.
    pub to_version: u32,
    /// The function that performs the migration.
    pub migrate: MigrationFn,
}

const DESCRIPTORS_TABLE_DEF: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("wallet_descriptors");

fn migrate_v1_to_v2(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(DESCRIPTORS_TABLE_DEF)?;
    wtxn.commit()?;
    Ok(())
}

const RELAY_CONFIGS_TABLE_DEF: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("relay_configs");

fn migrate_v2_to_v3(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(RELAY_CONFIGS_TABLE_DEF)?;
    wtxn.commit()?;
    Ok(())
}

const CONFIG_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("config");

fn migrate_v3_to_v4(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(CONFIG_TABLE_DEF)?;
    wtxn.commit()?;
    Ok(())
}

/// v4 → v5: introduce descriptor versioning. Every row in
/// `wallet_descriptors` is re-keyed from `group_pubkey` (32 bytes) to
/// `group_pubkey || version_be(1)` (36 bytes). Payloads are not decrypted;
/// the missing `version` / `previous_descriptor_hash` fields materialize on
/// next read via `#[serde(default)]`.
fn migrate_v4_to_v5(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    {
        let mut table = wtxn.open_table(DESCRIPTORS_TABLE_DEF)?;
        // Collect only the legacy 32-byte keys up front. Avoid materializing
        // the encrypted payloads here: on large vaults / mobile, doubling
        // every row in memory before rewriting is wasteful. The payload is
        // re-read row-by-row below inside the same transaction.
        //
        // Rows already in versioned form (36 bytes) are left untouched so
        // re-running the migration is a no-op.
        let mut legacy_keys: Vec<[u8; 32]> = Vec::new();
        for entry in table.iter()? {
            let (k, _v) = entry?;
            let key_bytes = k.value();
            match key_bytes.len() {
                32 => {
                    let mut old = [0u8; 32];
                    old.copy_from_slice(key_bytes);
                    legacy_keys.push(old);
                }
                36 => {}
                other => {
                    return Err(KeepError::Migration(format!(
                        "wallet_descriptors row has unexpected key length {other}, refusing to migrate"
                    )));
                }
            }
        }
        for old in legacy_keys {
            let mut new_key = [0u8; 36];
            new_key[..32].copy_from_slice(&old);
            new_key[32..36].copy_from_slice(&1u32.to_be_bytes());
            // Refuse to overwrite an existing v5 row at the rekeyed location.
            // Such a row should never exist (the source is a legacy 32-byte
            // key for the same group at version 1), but if it does, we must
            // not silently clobber it.
            if table.get(new_key.as_slice())?.is_some() {
                return Err(KeepError::Migration(format!(
                    "wallet_descriptors already contains a versioned row at {}, refusing to overwrite during v4->v5 migration",
                    hex::encode(new_key)
                )));
            }
            let value: Vec<u8> = table
                .get(old.as_slice())?
                .ok_or_else(|| {
                    KeepError::Migration(format!(
                        "wallet_descriptors row {} vanished mid-migration",
                        hex::encode(old)
                    ))
                })?
                .value()
                .to_vec();
            table.insert(new_key.as_slice(), value.as_slice())?;
            table.remove(old.as_slice())?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

const SECRETS_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secrets");

/// v5 → v6: introduce the `secrets` table for arbitrary-secret records
/// (passwords, API tokens, notes). Creating the empty table is the whole
/// migration; existing rows are untouched. Idempotent: opening a table that
/// already exists is a no-op.
fn migrate_v5_to_v6(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(SECRETS_TABLE_DEF)?;
    wtxn.commit()?;
    Ok(())
}

fn get_migrations() -> Vec<Migration> {
    vec![
        Migration {
            from_version: 1,
            to_version: 2,
            migrate: migrate_v1_to_v2,
        },
        Migration {
            from_version: 2,
            to_version: 3,
            migrate: migrate_v2_to_v3,
        },
        Migration {
            from_version: 3,
            to_version: 4,
            migrate: migrate_v3_to_v4,
        },
        Migration {
            from_version: 4,
            to_version: 5,
            migrate: migrate_v4_to_v5,
        },
        Migration {
            from_version: 5,
            to_version: 6,
            migrate: migrate_v5_to_v6,
        },
    ]
}

/// Read the schema version from the database.
pub fn read_schema_version(db: &Database) -> Result<Option<u32>> {
    let rtxn = db.begin_read()?;

    let table = match rtxn.open_table(METADATA_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let Some(value) = table.get(SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };

    let bytes: [u8; 4] = value
        .value()
        .try_into()
        .map_err(|_| KeepError::Migration("corrupted schema version".into()))?;

    Ok(Some(u32::from_le_bytes(bytes)))
}

/// Write the schema version to the database.
pub fn write_schema_version(db: &Database, version: u32) -> Result<()> {
    let wtxn = db.begin_write()?;
    {
        let mut table = wtxn.open_table(METADATA_TABLE)?;
        table.insert(SCHEMA_VERSION_KEY, version.to_le_bytes().as_slice())?;
    }
    wtxn.commit()?;
    Ok(())
}

/// Initialize the schema version for a new database.
pub fn initialize_schema(db: &Database) -> Result<()> {
    let wtxn = db.begin_write()?;
    {
        let mut table = wtxn.open_table(METADATA_TABLE)?;
        if table.get(SCHEMA_VERSION_KEY)?.is_none() {
            table.insert(
                SCHEMA_VERSION_KEY,
                CURRENT_SCHEMA_VERSION.to_le_bytes().as_slice(),
            )?;
            debug!(
                version = CURRENT_SCHEMA_VERSION,
                "initialized schema version"
            );
        }
    }
    wtxn.commit()?;
    Ok(())
}

/// Result of running migrations.
#[derive(Debug)]
pub struct MigrationResult {
    /// The version before migrations ran.
    pub from_version: u32,
    /// The version after migrations completed.
    pub to_version: u32,
    /// The number of migrations that were executed.
    pub migrations_run: u32,
}

/// Run all pending migrations.
pub fn run_migrations(db: &Database) -> Result<MigrationResult> {
    let current_version = read_schema_version(db)?.unwrap_or(1);
    let target_version = CURRENT_SCHEMA_VERSION;

    if current_version > target_version {
        return Err(KeepError::Migration(
            "vault was created with a newer version of keep".into(),
        ));
    }

    if current_version == target_version {
        debug!(version = current_version, "schema is current");
        return Ok(MigrationResult {
            from_version: current_version,
            to_version: current_version,
            migrations_run: 0,
        });
    }

    let migrations = get_migrations();
    let mut version = current_version;
    let mut migrations_run = 0;

    while version < target_version {
        let migration = migrations
            .iter()
            .find(|m| m.from_version == version)
            .ok_or_else(|| {
                KeepError::Migration("unable to migrate vault to current version".into())
            })?;

        info!(
            from = migration.from_version,
            to = migration.to_version,
            "running migration"
        );

        (migration.migrate)(db)?;

        write_schema_version(db, migration.to_version)?;
        version = migration.to_version;
        migrations_run += 1;

        info!(version, "migration complete");
    }

    Ok(MigrationResult {
        from_version: current_version,
        to_version: target_version,
        migrations_run,
    })
}

/// Check if the database is compatible with this version of keep.
pub fn check_compatibility(db: &Database) -> Result<()> {
    let version = read_schema_version(db)?.unwrap_or(1);

    if version > CURRENT_SCHEMA_VERSION {
        return Err(KeepError::Migration(
            "vault was created with a newer version of keep".into(),
        ));
    }

    Ok(())
}

/// Check if migrations are needed.
pub fn needs_migration(db: &Database) -> Result<bool> {
    let version = read_schema_version(db)?.unwrap_or(1);
    Ok(version < CURRENT_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_db() -> (tempfile::TempDir, Database) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::create(&db_path).unwrap();
        (dir, db)
    }

    #[test]
    fn test_initialize_schema() {
        let (_dir, db) = create_test_db();
        assert!(read_schema_version(&db).unwrap().is_none());
        initialize_schema(&db).unwrap();
        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn test_initialize_schema_idempotent() {
        let (_dir, db) = create_test_db();
        initialize_schema(&db).unwrap();
        initialize_schema(&db).unwrap();
        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn test_run_migrations_current_version() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION).unwrap();
        let result = run_migrations(&db).unwrap();
        assert_eq!(result.from_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(result.to_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(result.migrations_run, 0);
    }

    #[test]
    fn test_check_compatibility_newer_version() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION + 1).unwrap();
        let result = check_compatibility(&db);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("newer version"));
    }

    #[test]
    fn test_needs_migration() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION).unwrap();
        assert!(!needs_migration(&db).unwrap());
    }

    #[test]
    fn test_v4_to_v5_rekeys_descriptor_rows() {
        let (_dir, db) = create_test_db();
        // Seed a legacy 32-byte-keyed row.
        let legacy_key = [9u8; 32];
        let payload = b"opaque-encrypted-payload".to_vec();
        {
            let wtxn = db.begin_write().unwrap();
            {
                let mut table = wtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
                table
                    .insert(legacy_key.as_slice(), payload.as_slice())
                    .unwrap();
            }
            wtxn.commit().unwrap();
        }

        migrate_v4_to_v5(&db).unwrap();

        let rtxn = db.begin_read().unwrap();
        let table = rtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
        assert!(table.get(legacy_key.as_slice()).unwrap().is_none());
        let mut expected_new = [0u8; 36];
        expected_new[..32].copy_from_slice(&legacy_key);
        expected_new[32..36].copy_from_slice(&1u32.to_be_bytes());
        let row = table.get(expected_new.as_slice()).unwrap().unwrap();
        assert_eq!(row.value(), payload.as_slice());
    }

    #[test]
    fn test_v4_to_v5_refuses_to_clobber_existing_v5_row() {
        let (_dir, db) = create_test_db();
        let group = [4u8; 32];
        let legacy_payload = b"legacy".to_vec();
        let new_payload = b"already-v5".to_vec();
        let mut versioned_key = [0u8; 36];
        versioned_key[..32].copy_from_slice(&group);
        versioned_key[32..36].copy_from_slice(&1u32.to_be_bytes());

        {
            let wtxn = db.begin_write().unwrap();
            {
                let mut table = wtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
                table
                    .insert(group.as_slice(), legacy_payload.as_slice())
                    .unwrap();
                table
                    .insert(versioned_key.as_slice(), new_payload.as_slice())
                    .unwrap();
            }
            wtxn.commit().unwrap();
        }

        let err = migrate_v4_to_v5(&db).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
    }

    #[test]
    fn test_v4_to_v5_rejects_unexpected_key_length() {
        let (_dir, db) = create_test_db();
        let weird_key = vec![0xABu8; 20];
        {
            let wtxn = db.begin_write().unwrap();
            {
                let mut table = wtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
                table.insert(weird_key.as_slice(), b"x".as_slice()).unwrap();
            }
            wtxn.commit().unwrap();
        }
        let err = migrate_v4_to_v5(&db).unwrap_err();
        assert!(err.to_string().contains("unexpected key length"));
    }

    #[test]
    fn test_v4_to_v5_is_idempotent() {
        let (_dir, db) = create_test_db();
        let legacy_key = [3u8; 32];
        let payload = b"payload".to_vec();
        {
            let wtxn = db.begin_write().unwrap();
            {
                let mut table = wtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
                table
                    .insert(legacy_key.as_slice(), payload.as_slice())
                    .unwrap();
            }
            wtxn.commit().unwrap();
        }

        migrate_v4_to_v5(&db).unwrap();
        migrate_v4_to_v5(&db).unwrap();

        let rtxn = db.begin_read().unwrap();
        let table = rtxn.open_table(DESCRIPTORS_TABLE_DEF).unwrap();
        let mut count = 0;
        for entry in table.iter().unwrap() {
            let (k, _) = entry.unwrap();
            assert_eq!(k.value().len(), 36);
            count += 1;
        }
        assert_eq!(count, 1);
    }

    /// End-to-end runner coverage for a v1 vault walking forward to the
    /// current schema version. Until now only the no-op "already current"
    /// case was tested at the runner level; this exercises the loop that
    /// looks up each step's migration, runs it, writes the new version, and
    /// stops at CURRENT_SCHEMA_VERSION.
    #[test]
    fn run_migrations_progresses_from_v1_to_current() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, 1).unwrap();
        let result = run_migrations(&db).unwrap();
        assert_eq!(result.from_version, 1);
        assert_eq!(result.to_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(result.migrations_run, CURRENT_SCHEMA_VERSION - 1);
        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );
    }

    /// `read_schema_version().unwrap_or(1)` means an uninitialized vault is
    /// treated as v1. Pin so a future refactor that swaps the fallback (e.g.
    /// to `CURRENT_SCHEMA_VERSION`) is caught: that would silently mask a
    /// real "needs migration" state on fresh databases.
    #[test]
    fn run_migrations_treats_uninitialized_vault_as_v1() {
        let (_dir, db) = create_test_db();
        assert!(read_schema_version(&db).unwrap().is_none());
        let result = run_migrations(&db).unwrap();
        assert_eq!(result.from_version, 1);
        assert_eq!(result.to_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(result.migrations_run, CURRENT_SCHEMA_VERSION - 1);
    }

    /// Opening a vault written by a NEWER keep build must refuse rather than
    /// silently downgrade or run forward migrations that don't exist. The
    /// CLI surfaces this with `keep migrate status` showing the error before
    /// any data is touched.
    #[test]
    fn run_migrations_refuses_future_schema_version() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION + 7).unwrap();
        let err = run_migrations(&db).unwrap_err();
        assert!(err.to_string().contains("newer version"), "got {err}");
        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION + 7),
            "the persisted version must not be rewritten on a refusal"
        );
    }

    /// `needs_migration()` is what `keep migrate status` displays. Pin the
    /// transitional case where it must report TRUE on a v1 vault.
    #[test]
    fn needs_migration_true_when_below_current() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, 1).unwrap();
        assert!(needs_migration(&db).unwrap());
    }

    /// `check_compatibility()` runs on EVERY open via `RedbBackend::open`, so
    /// the happy path needs an explicit pin: a vault at the current version
    /// must NOT raise.
    #[test]
    fn check_compatibility_passes_at_current_version() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION).unwrap();
        check_compatibility(&db).unwrap();
    }
}
