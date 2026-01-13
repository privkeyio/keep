#![forbid(unsafe_code)]

use redb::{Database, ReadableTable, TableDefinition};
use tracing::{debug, info};

use crate::error::{KeepError, Result};

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

const SCHEMA_VERSION_KEY: &str = "schema_version";

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

pub type MigrationFn = fn(&Database) -> Result<()>;

pub struct Migration {
    pub from_version: u32,
    pub to_version: u32,
    pub migrate: MigrationFn,
}

fn get_migrations() -> Vec<Migration> {
    vec![]
}

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

pub fn write_schema_version(db: &Database, version: u32) -> Result<()> {
    let wtxn = db.begin_write()?;
    {
        let mut table = wtxn.open_table(METADATA_TABLE)?;
        table.insert(SCHEMA_VERSION_KEY, version.to_le_bytes().as_slice())?;
    }
    wtxn.commit()?;
    Ok(())
}

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

#[derive(Debug)]
pub struct MigrationResult {
    pub from_version: u32,
    pub to_version: u32,
    pub migrations_run: u32,
}

pub fn run_migrations(db: &Database) -> Result<MigrationResult> {
    let current_version = read_schema_version(db)?.unwrap_or(1);
    let target_version = CURRENT_SCHEMA_VERSION;

    if current_version > target_version {
        return Err(KeepError::Migration(format!(
            "vault schema version {} is newer than supported version {}",
            current_version, target_version
        )));
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
                KeepError::Migration(format!("no migration path from version {}", version))
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

pub fn check_compatibility(db: &Database) -> Result<()> {
    let version = read_schema_version(db)?.unwrap_or(1);

    if version > CURRENT_SCHEMA_VERSION {
        return Err(KeepError::Migration(format!(
            "vault requires keep version that supports schema {}, current supports up to {}",
            version, CURRENT_SCHEMA_VERSION
        )));
    }

    Ok(())
}

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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires keep version"));
    }

    #[test]
    fn test_needs_migration() {
        let (_dir, db) = create_test_db();
        write_schema_version(&db, CURRENT_SCHEMA_VERSION).unwrap();
        assert!(!needs_migration(&db).unwrap());
    }
}
