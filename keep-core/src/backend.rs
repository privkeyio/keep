//! Pluggable storage backends for encrypted key storage.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{PoisonError, RwLock};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{error, info, warn};

use crate::error::{KeepError, Result, StorageError};
use crate::migration;

fn lock_error<T>(_: PoisonError<T>) -> KeepError {
    KeepError::Runtime("lock poisoned".into())
}

/// Table name for key records.
pub const KEYS_TABLE: &str = "keys";
/// Table name for FROST shares.
pub const SHARES_TABLE: &str = "shares";
/// Table name for wallet descriptors.
pub const DESCRIPTORS_TABLE: &str = "wallet_descriptors";
/// Table name for relay configurations.
pub const RELAY_CONFIGS_TABLE: &str = "relay_configs";
/// Table name for application configuration.
pub const CONFIG_TABLE: &str = "config";
/// Table name for key health status records.
pub const HEALTH_STATUS_TABLE: &str = "key_health_status";

/// Trait for pluggable storage backends.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait StorageBackend: Send + Sync {
    /// Get a value by key from the specified table.
    fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Store a key-value pair in the specified table.
    fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<()>;
    /// Delete a key from the specified table. Returns true if the key existed.
    fn delete(&self, table: &str, key: &[u8]) -> Result<bool>;
    /// List all key-value pairs in the specified table.
    fn list(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
    /// Create a table if it doesn't exist.
    fn create_table(&self, table: &str) -> Result<()>;

    /// Store multiple key-value pairs in a single atomic operation.
    fn put_batch(&self, table: &str, entries: &[(&[u8], &[u8])]) -> Result<()> {
        for (key, value) in entries {
            self.put(table, key, value)?;
        }
        Ok(())
    }

    /// Get the current schema version.
    ///
    /// Default implementation returns `CURRENT_SCHEMA_VERSION`, suitable for
    /// in-memory backends that don't persist schema versions.
    fn schema_version(&self) -> Result<u32> {
        Ok(migration::CURRENT_SCHEMA_VERSION)
    }

    /// Check if migrations are needed.
    ///
    /// Default implementation returns `false`, suitable for in-memory backends
    /// that always start fresh without persisted data to migrate.
    fn needs_migration(&self) -> Result<bool> {
        Ok(false)
    }

    /// Run pending migrations.
    ///
    /// Default implementation is a no-op that reports zero migrations run,
    /// suitable for in-memory backends that don't persist data between sessions.
    fn run_migrations(&self) -> Result<migration::MigrationResult> {
        Ok(migration::MigrationResult {
            from_version: migration::CURRENT_SCHEMA_VERSION,
            to_version: migration::CURRENT_SCHEMA_VERSION,
            migrations_run: 0,
        })
    }
}

const KEYS_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");
const SHARES_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("shares");
const DESCRIPTORS_TABLE_DEF: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("wallet_descriptors");
const RELAY_CONFIGS_TABLE_DEF: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("relay_configs");
const CONFIG_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("config");
const HEALTH_STATUS_TABLE_DEF: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("key_health_status");

/// Redb-based storage backend (default).
pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    /// Create a new database at the given path.
    pub fn create(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        migration::initialize_schema(&db)?;
        Ok(Self { db })
    }

    /// Open an existing database at the given path.
    /// Retries on Windows to handle delayed file handle release.
    /// Auto-upgrades from older redb file formats.
    pub fn open(path: &Path) -> Result<Self> {
        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY_MS: u64 = 50;

        let mut last_err = None;
        for _ in 0..MAX_RETRIES {
            match Database::open(path) {
                Ok(db) => {
                    migration::check_compatibility(&db)?;
                    let result = migration::run_migrations(&db)?;
                    if result.migrations_run > 0 {
                        info!(
                            count = result.migrations_run,
                            "vault schema migration completed"
                        );
                    }
                    return Ok(Self { db });
                }
                Err(redb::DatabaseError::UpgradeRequired(old_version)) => {
                    warn!(
                        old_version,
                        "redb file format upgrade required, migrating automatically"
                    );
                    return Self::upgrade_file_format(path);
                }
                Err(e) => {
                    let is_retryable = matches!(
                        &e,
                        redb::DatabaseError::Storage(redb::StorageError::Io(io_err))
                            if io_err.kind() == std::io::ErrorKind::PermissionDenied
                    ) || matches!(&e, redb::DatabaseError::DatabaseAlreadyOpen);

                    if is_retryable {
                        last_err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }
        Err(last_err
            .map(|e| e.into())
            .unwrap_or_else(|| StorageError::database("open failed after retries").into()))
    }

    /// Upgrade from an older redb file format by copying all data.
    fn upgrade_file_format(path: &Path) -> Result<Self> {
        let old_db = redb2::Database::open(path).map_err(|e| {
            StorageError::database(format!("failed to open old database for migration: {e}"))
        })?;

        let table_names: &[&str] = &[
            KEYS_TABLE,
            SHARES_TABLE,
            DESCRIPTORS_TABLE,
            RELAY_CONFIGS_TABLE,
            CONFIG_TABLE,
            HEALTH_STATUS_TABLE,
        ];

        type TableEntries = Vec<(Vec<u8>, Vec<u8>)>;
        let mut table_data: Vec<(&str, TableEntries)> = Vec::new();
        let old_schema_version;
        {
            use redb2::ReadableTable as _;

            let rtxn = old_db
                .begin_read()
                .map_err(|e| StorageError::database(format!("failed to read old database: {e}")))?;
            for &name in table_names {
                let table_def: redb2::TableDefinition<&[u8], &[u8]> =
                    redb2::TableDefinition::new(name);
                match rtxn.open_table(table_def) {
                    Ok(table) => {
                        let entries: Vec<(Vec<u8>, Vec<u8>)> = table
                            .iter()
                            .map_err(|e| {
                                StorageError::database(format!(
                                    "failed to iterate table {name}: {e}"
                                ))
                            })?
                            .map(|r| {
                                let (k, v) = r.map_err(|e| {
                                    StorageError::database(format!(
                                        "failed to read entry in table {name}: {e}"
                                    ))
                                })?;
                                Ok((k.value().to_vec(), v.value().to_vec()))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        info!(
                            table = name,
                            count = entries.len(),
                            "read table for migration"
                        );
                        table_data.push((name, entries));
                    }
                    Err(redb2::TableError::TableDoesNotExist(_)) => {}
                    Err(e) => {
                        return Err(StorageError::database(format!(
                            "failed to open table {name}: {e}"
                        ))
                        .into());
                    }
                }
            }

            let metadata_def: redb2::TableDefinition<&str, &[u8]> =
                redb2::TableDefinition::new("metadata");
            old_schema_version = match rtxn.open_table(metadata_def) {
                Ok(table) => table
                    .get("schema_version")
                    .map_err(|e| {
                        StorageError::database(format!(
                            "failed to read schema_version from old database: {e}"
                        ))
                    })?
                    .and_then(|v| <[u8; 4]>::try_from(v.value()).ok())
                    .map(u32::from_le_bytes),
                Err(redb2::TableError::TableDoesNotExist(_)) => None,
                Err(e) => {
                    return Err(StorageError::database(format!(
                        "failed to open metadata table: {e}"
                    ))
                    .into());
                }
            };
        }
        drop(old_db);

        let backup_path = path.with_extension("db.old");
        if backup_path.exists() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let alt = path.with_extension(format!("db.old.{ts}"));
            std::fs::rename(&backup_path, &alt).map_err(|e| {
                StorageError::database(format!(
                    "failed to move existing backup before migration: {e}"
                ))
            })?;
            warn!(?alt, "moved existing backup aside");
        }
        std::fs::rename(path, &backup_path)?;
        info!(?backup_path, "backed up old database");

        let new_db = Database::create(path).map_err(|e| {
            if let Err(re) = std::fs::rename(&backup_path, path) {
                error!(
                    "failed to restore backup after migration failure: {re}; \
                     backup is at {backup_path:?}"
                );
            }
            StorageError::database(format!("failed to create new database: {e}"))
        })?;

        let write_result: Result<()> = (|| {
            let wtxn = new_db.begin_write()?;
            for (name, entries) in &table_data {
                let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(name);
                let mut table = wtxn.open_table(table_def)?;
                for (key, value) in entries {
                    table.insert(key.as_slice(), value.as_slice())?;
                }
            }
            {
                let metadata: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
                let mut table = wtxn.open_table(metadata)?;
                let version = old_schema_version.unwrap_or(1);
                table.insert("schema_version", version.to_le_bytes().as_slice())?;
            }
            wtxn.commit()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            drop(new_db);
            let _ = std::fs::remove_file(path);
            if let Err(re) = std::fs::rename(&backup_path, path) {
                error!(
                    "failed to restore backup after write failure: {re}; \
                     backup is at {backup_path:?}"
                );
            }
            return Err(e);
        }

        info!("database file format upgrade complete");

        let migrate_result: Result<migration::MigrationResult> = (|| {
            migration::check_compatibility(&new_db)?;
            migration::run_migrations(&new_db)
        })();
        let result = match migrate_result {
            Ok(r) => r,
            Err(e) => {
                drop(new_db);
                let _ = std::fs::remove_file(path);
                if let Err(re) = std::fs::rename(&backup_path, path) {
                    error!(
                        "failed to restore backup after migration failure: {re}; \
                         backup is at {backup_path:?}"
                    );
                }
                return Err(e);
            }
        };
        if result.migrations_run > 0 {
            info!(
                count = result.migrations_run,
                "schema migration completed after file format upgrade"
            );
        }

        Ok(Self { db: new_db })
    }

    fn table_def(
        &self,
        name: &str,
    ) -> Result<TableDefinition<'static, &'static [u8], &'static [u8]>> {
        match name {
            KEYS_TABLE => Ok(KEYS_TABLE_DEF),
            SHARES_TABLE => Ok(SHARES_TABLE_DEF),
            DESCRIPTORS_TABLE => Ok(DESCRIPTORS_TABLE_DEF),
            RELAY_CONFIGS_TABLE => Ok(RELAY_CONFIGS_TABLE_DEF),
            CONFIG_TABLE => Ok(CONFIG_TABLE_DEF),
            HEALTH_STATUS_TABLE => Ok(HEALTH_STATUS_TABLE_DEF),
            _ => Err(StorageError::database(format!("unknown table: {name}")).into()),
        }
    }
}

impl StorageBackend for RedbBackend {
    fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(self.table_def(table)?)?;
        Ok(tbl.get(key)?.map(|v| v.value().to_vec()))
    }

    fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        wtxn.open_table(self.table_def(table)?)?
            .insert(key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
        let wtxn = self.db.begin_write()?;
        let existed = wtxn
            .open_table(self.table_def(table)?)?
            .remove(key)?
            .is_some();
        wtxn.commit()?;
        Ok(existed)
    }

    fn list(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(self.table_def(table)?)?;
        tbl.iter()?
            .map(|result| {
                let (k, v) = result?;
                Ok((k.value().to_vec(), v.value().to_vec()))
            })
            .collect()
    }

    fn create_table(&self, table: &str) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        wtxn.open_table(self.table_def(table)?)?;
        wtxn.commit()?;
        Ok(())
    }

    fn put_batch(&self, table: &str, entries: &[(&[u8], &[u8])]) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut tbl = wtxn.open_table(self.table_def(table)?)?;
            for (key, value) in entries {
                tbl.insert(*key, *value)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    fn schema_version(&self) -> Result<u32> {
        Ok(migration::read_schema_version(&self.db)?.unwrap_or(1))
    }

    fn needs_migration(&self) -> Result<bool> {
        migration::needs_migration(&self.db)
    }

    fn run_migrations(&self) -> Result<migration::MigrationResult> {
        migration::run_migrations(&self.db)
    }
}

type TableData = BTreeMap<Vec<u8>, Vec<u8>>;

/// In-memory storage backend for testing.
pub struct MemoryBackend {
    tables: RwLock<BTreeMap<String, TableData>>,
}

impl MemoryBackend {
    /// Create a new in-memory backend.
    pub fn new() -> Self {
        Self {
            tables: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryBackend {
    fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tables = self.tables.read().map_err(lock_error)?;
        Ok(tables.get(table).and_then(|t| t.get(key).cloned()))
    }

    fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.tables
            .write()
            .map_err(lock_error)?
            .entry(table.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
        let mut tables = self.tables.write().map_err(lock_error)?;
        Ok(tables
            .get_mut(table)
            .map(|t| t.remove(key).is_some())
            .unwrap_or(false))
    }

    fn list(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tables = self.tables.read().map_err(lock_error)?;
        Ok(tables
            .get(table)
            .map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }

    fn create_table(&self, table: &str) -> Result<()> {
        self.tables
            .write()
            .map_err(lock_error)?
            .entry(table.to_string())
            .or_default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_backend_operations(backend: &dyn StorageBackend) {
        backend.create_table(KEYS_TABLE).unwrap();

        assert!(backend.get(KEYS_TABLE, b"key1").unwrap().is_none());

        backend.put(KEYS_TABLE, b"key1", b"value1").unwrap();
        assert_eq!(
            backend.get(KEYS_TABLE, b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        backend.put(KEYS_TABLE, b"key2", b"value2").unwrap();
        let entries = backend.list(KEYS_TABLE).unwrap();
        assert_eq!(entries.len(), 2);

        assert!(backend.delete(KEYS_TABLE, b"key1").unwrap());
        assert!(backend.get(KEYS_TABLE, b"key1").unwrap().is_none());
        assert!(!backend.delete(KEYS_TABLE, b"key1").unwrap());
    }

    #[test]
    fn test_memory_backend() {
        let backend = MemoryBackend::new();
        test_backend_operations(&backend);
    }

    #[test]
    fn test_redb_backend() {
        let dir = tempdir().unwrap();
        let backend = RedbBackend::create(&dir.path().join("test.db")).unwrap();
        test_backend_operations(&backend);
    }

    #[test]
    fn test_unknown_table_rejected() {
        let dir = tempdir().unwrap();
        let backend = RedbBackend::create(&dir.path().join("test.db")).unwrap();
        assert!(backend.create_table("unknown").is_err());
    }
}
