// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt;
use parking_lot::RwLock;
use tracing::{debug, warn};

use crate::error::{FrostNetError, Result};

pub trait NonceStore: Send + Sync {
    fn record(&self, session_id: &[u8; 32]) -> Result<()>;
    fn is_consumed(&self, session_id: &[u8; 32]) -> bool;
    fn count(&self) -> usize;
    fn prune_if_needed(&self) {}
}

pub struct FileNonceStore {
    path: PathBuf,
    consumed: Arc<RwLock<HashSet<[u8; 32]>>>,
    insertion_order: Arc<RwLock<VecDeque<[u8; 32]>>>,
    max_entries: usize,
}

impl FileNonceStore {
    pub fn new(path: &Path) -> Result<Self> {
        let consumed = Arc::new(RwLock::new(HashSet::new()));
        let insertion_order = Arc::new(RwLock::new(VecDeque::new()));

        if path.exists() {
            let file = File::open(path)
                .map_err(|e| FrostNetError::Session(format!("Failed to open nonce store: {e}")))?;

            file.lock_exclusive()
                .map_err(|e| FrostNetError::Session(format!("Failed to lock nonce store: {e}")))?;

            let reader = BufReader::new(&file);

            let mut guard = consumed.write();
            for line in reader.lines() {
                let line = line.map_err(|e| {
                    FrostNetError::Session(format!("Failed to read nonce store: {e}"))
                })?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let bytes = hex::decode(line).map_err(|e| {
                    FrostNetError::Session(format!("Invalid hex in nonce store: {e}"))
                })?;

                if bytes.len() != 32 {
                    warn!(line = %line, "Skipping invalid entry in nonce store");
                    continue;
                }

                let mut session_id = [0u8; 32];
                session_id.copy_from_slice(&bytes);
                if guard.insert(session_id) {
                    insertion_order.write().push_back(session_id);
                }
            }
            debug!(count = guard.len(), path = ?path, "Loaded consumed session IDs");

            FileExt::unlock(&file).map_err(|e| {
                FrostNetError::Session(format!("Failed to unlock nonce store: {e}"))
            })?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            consumed,
            insertion_order,
            max_entries: DEFAULT_MAX_ENTRIES,
        })
    }
}

impl NonceStore for FileNonceStore {
    fn record(&self, session_id: &[u8; 32]) -> Result<()> {
        let mut guard = self.consumed.write();
        if guard.contains(session_id) {
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| FrostNetError::Session(format!("Failed to open nonce store: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
            {
                warn!(path = ?self.path, error = %e, "Failed to set nonce store permissions");
            }
        }

        file.lock_exclusive()
            .map_err(|e| FrostNetError::Session(format!("Failed to lock nonce store: {e}")))?;

        let hex_id = hex::encode(session_id);
        let write_result = writeln!(file, "{hex_id}");
        let sync_result = if write_result.is_ok() {
            file.sync_all()
        } else {
            Ok(())
        };

        FileExt::unlock(&file)
            .map_err(|e| FrostNetError::Session(format!("Failed to unlock nonce store: {e}")))?;

        write_result
            .map_err(|e| FrostNetError::Session(format!("Failed to write to nonce store: {e}")))?;

        sync_result
            .map_err(|e| FrostNetError::Session(format!("Failed to sync nonce store: {e}")))?;

        guard.insert(*session_id);
        self.insertion_order.write().push_back(*session_id);
        drop(guard);
        debug!(session_id = %hex_id, "Recorded consumed session ID");
        self.prune_if_needed();

        Ok(())
    }

    fn is_consumed(&self, session_id: &[u8; 32]) -> bool {
        self.consumed.read().contains(session_id)
    }

    fn count(&self) -> usize {
        self.consumed.read().len()
    }

    fn prune_if_needed(&self) {
        let mut consumed = self.consumed.write();
        let mut order = self.insertion_order.write();

        let before = consumed.len();
        while consumed.len() > self.max_entries {
            if let Some(oldest) = order.pop_front() {
                consumed.remove(&oldest);
            } else {
                break;
            }
        }

        if consumed.len() < before {
            if let Err(e) = rewrite_nonce_file(&self.path, order.iter()) {
                warn!(error = %e, "Failed to rewrite nonce store after pruning");
            }
        }
    }
}

fn rewrite_nonce_file<'a>(
    path: &Path,
    entries: impl Iterator<Item = &'a [u8; 32]>,
) -> std::result::Result<(), std::io::Error> {
    let tmp_path = path.with_extension("tmp");
    let mut file = File::create(&tmp_path)?;
    for entry in entries {
        writeln!(file, "{}", hex::encode(entry))?;
    }
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
        {
            warn!(path = ?tmp_path, error = %e, "Failed to set nonce store permissions");
        }
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

const DEFAULT_MAX_ENTRIES: usize = 100_000;

pub struct MemoryNonceStore {
    consumed: Arc<RwLock<HashSet<[u8; 32]>>>,
    insertion_order: Arc<RwLock<VecDeque<[u8; 32]>>>,
    max_entries: usize,
}

impl MemoryNonceStore {
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            consumed: Arc::new(RwLock::new(HashSet::new())),
            insertion_order: Arc::new(RwLock::new(VecDeque::new())),
            max_entries,
        }
    }
}

impl Default for MemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for MemoryNonceStore {
    fn record(&self, session_id: &[u8; 32]) -> Result<()> {
        {
            let mut consumed = self.consumed.write();
            if consumed.insert(*session_id) {
                self.insertion_order.write().push_back(*session_id);
            }
        }
        self.prune_if_needed();
        Ok(())
    }

    fn is_consumed(&self, session_id: &[u8; 32]) -> bool {
        self.consumed.read().contains(session_id)
    }

    fn count(&self) -> usize {
        self.consumed.read().len()
    }

    fn prune_if_needed(&self) {
        let mut consumed = self.consumed.write();
        let mut order = self.insertion_order.write();

        while consumed.len() > self.max_entries {
            if let Some(oldest) = order.pop_front() {
                consumed.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_memory_store() {
        let store = MemoryNonceStore::new();
        let session_id = [1u8; 32];

        assert!(!store.is_consumed(&session_id));
        store.record(&session_id).unwrap();
        assert!(store.is_consumed(&session_id));
        assert_eq!(store.count(), 1);
    }

    #[test]
    #[cfg_attr(windows, ignore = "file locking behaves differently on Windows")]
    fn test_file_store_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");

        let session_id1 = [1u8; 32];
        let session_id2 = [2u8; 32];

        {
            let store = FileNonceStore::new(&path).unwrap();
            assert!(!store.is_consumed(&session_id1));
            store.record(&session_id1).unwrap();
            store.record(&session_id2).unwrap();
            assert!(store.is_consumed(&session_id1));
            assert!(store.is_consumed(&session_id2));
        }

        {
            let store = FileNonceStore::new(&path).unwrap();
            assert!(store.is_consumed(&session_id1));
            assert!(store.is_consumed(&session_id2));
            assert_eq!(store.count(), 2);
        }
    }

    #[test]
    #[cfg_attr(windows, ignore = "file locking behaves differently on Windows")]
    fn test_file_store_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("new_nonces.log");

        let store = FileNonceStore::new(&path).unwrap();
        assert_eq!(store.count(), 0);

        let session_id = [42u8; 32];
        store.record(&session_id).unwrap();
        assert!(store.is_consumed(&session_id));
    }

    #[test]
    #[cfg_attr(windows, ignore = "file locking behaves differently on Windows")]
    fn test_idempotent_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");

        let store = FileNonceStore::new(&path).unwrap();
        let session_id = [1u8; 32];

        store.record(&session_id).unwrap();
        store.record(&session_id).unwrap();
        store.record(&session_id).unwrap();

        assert_eq!(store.count(), 1);
    }
}
