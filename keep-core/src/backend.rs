//! Pluggable storage backends for encrypted key storage.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;

use redb::{Database, ReadableTable, TableDefinition};

use crate::error::{KeepError, Result};

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
}

const KEYS_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("keys");
const SHARES_TABLE_DEF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("shares");

/// Redb-based storage backend (default).
pub struct RedbBackend {
    db: Database,
    table_names: RwLock<BTreeMap<String, &'static str>>,
}

impl RedbBackend {
    /// Create a new database at the given path.
    pub fn create(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        Ok(Self {
            db,
            table_names: RwLock::new(BTreeMap::new()),
        })
    }

    /// Open an existing database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::open(path)?;
        Ok(Self {
            db,
            table_names: RwLock::new(BTreeMap::new()),
        })
    }

    fn table_def(
        &self,
        name: &str,
    ) -> Result<TableDefinition<'static, &'static [u8], &'static [u8]>> {
        match name {
            KEYS_TABLE => Ok(KEYS_TABLE_DEF),
            SHARES_TABLE => Ok(SHARES_TABLE_DEF),
            _ => {
                let mut cache = self
                    .table_names
                    .write()
                    .map_err(|e| KeepError::Other(e.to_string()))?;
                let static_name: &'static str = cache
                    .entry(name.to_string())
                    .or_insert_with(|| Box::leak(name.to_string().into_boxed_str()));
                Ok(TableDefinition::new(static_name))
            }
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
        let tables = self
            .tables
            .read()
            .map_err(|e| KeepError::Other(e.to_string()))?;
        Ok(tables.get(table).and_then(|t| t.get(key).cloned()))
    }

    fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let mut tables = self
            .tables
            .write()
            .map_err(|e| KeepError::Other(e.to_string()))?;
        tables
            .entry(table.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
        let mut tables = self
            .tables
            .write()
            .map_err(|e| KeepError::Other(e.to_string()))?;
        Ok(tables
            .get_mut(table)
            .map(|t| t.remove(key).is_some())
            .unwrap_or(false))
    }

    fn list(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tables = self
            .tables
            .read()
            .map_err(|e| KeepError::Other(e.to_string()))?;
        Ok(tables
            .get(table)
            .map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }

    fn create_table(&self, table: &str) -> Result<()> {
        let mut tables = self
            .tables
            .write()
            .map_err(|e| KeepError::Other(e.to_string()))?;
        tables.entry(table.to_string()).or_default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_backend_operations(backend: &dyn StorageBackend) {
        backend.create_table("test").unwrap();

        assert!(backend.get("test", b"key1").unwrap().is_none());

        backend.put("test", b"key1", b"value1").unwrap();
        assert_eq!(
            backend.get("test", b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        backend.put("test", b"key2", b"value2").unwrap();
        let entries = backend.list("test").unwrap();
        assert_eq!(entries.len(), 2);

        assert!(backend.delete("test", b"key1").unwrap());
        assert!(backend.get("test", b"key1").unwrap().is_none());
        assert!(!backend.delete("test", b"key1").unwrap());
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
}
