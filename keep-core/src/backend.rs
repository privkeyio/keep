//! Pluggable storage backends for encrypted key storage.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{PoisonError, RwLock};

use redb::{Database, ReadableTable, TableDefinition};
use tracing::info;

use crate::error::{KeepError, Result};
use crate::migration;

fn lock_error<T>(_: PoisonError<T>) -> KeepError {
    KeepError::Other("lock poisoned".into())
}

/// Table name for key records.
pub const KEYS_TABLE: &str = "keys";
/// Table name for FROST shares.
pub const SHARES_TABLE: &str = "shares";

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
            .unwrap_or_else(|| KeepError::Other("database open failed after retries".into())))
    }

    fn table_def(
        &self,
        name: &str,
    ) -> Result<TableDefinition<'static, &'static [u8], &'static [u8]>> {
        match name {
            KEYS_TABLE => Ok(KEYS_TABLE_DEF),
            SHARES_TABLE => Ok(SHARES_TABLE_DEF),
            _ => Err(KeepError::Other(format!("unknown table: {}", name))),
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
