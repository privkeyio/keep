// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
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

        {
            // Lock the same sibling the writers lock, not the store itself,
            // and take it before checking whether the store exists.
            //
            // Reading under a lock on the store while `record` and the rewrite
            // path lock `<store>.lock` meant the reader and the writers took
            // locks on different inodes and never contended: this lock excluded
            // nothing at all. Loading the consumed set could therefore run
            // against a file being appended to or replaced underneath it, and
            // the guard would start life having missed entries. Checking
            // existence outside the lock had the same shape of hole: a store
            // created between the check and the load would be skipped, and the
            // guard would start empty with every consumed id reading available.
            let lock_path = path.with_extension("lock");
            let lock_file = {
                let mut opts = OpenOptions::new();
                opts.create(true).write(true).truncate(false);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(&lock_path).map_err(|e| {
                    FrostNetError::Session(format!("Failed to open nonce lock: {e}"))
                })?
            };
            lock_file
                .lock_exclusive()
                .map_err(|e| FrostNetError::Session(format!("Failed to lock nonce store: {e}")))?;

            let file = match File::open(path) {
                Ok(f) => Some(f),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(FrostNetError::Session(format!(
                        "Failed to open nonce store: {e}"
                    )))
                }
            };

            if let Some(file) = file {
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
                        // Refuse to load rather than skip. A short entry is a
                        // truncated append, so the record it lost is the most
                        // recently consumed session, and skipping it silently
                        // returns that session id to the available set: the exact
                        // replay this store exists to prevent, produced by the
                        // recovery path rather than by an attacker. An odd-length
                        // truncation already fails hard a few lines above, so this
                        // is the same corruption being answered the same way rather
                        // than a new failure mode.
                        return Err(FrostNetError::Session(format!(
                            "Nonce store entry is {} bytes, expected 32: the store is \
                         truncated or corrupt and cannot be trusted to prevent reuse",
                            bytes.len()
                        )));
                    }

                    let mut session_id = [0u8; 32];
                    session_id.copy_from_slice(&bytes);
                    if guard.insert(session_id) {
                        insertion_order.write().push_back(session_id);
                    }
                }
                debug!(count = guard.len(), path = ?path, "Loaded consumed session IDs");
            }

            // `lock_file` is declared before `file`, so it drops last: the lock
            // is released after the read completes. No explicit unlock, which
            // is what the error paths above already rely on. Unlocking `file`
            // here would target a handle that was never locked: a silent no-op
            // on Unix, and an error on Windows that would fail every load.
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

        let lock_path = self.path.with_extension("lock");
        let lock_file = {
            let mut opts = OpenOptions::new();
            opts.create(true).truncate(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&lock_path)
                .map_err(|e| FrostNetError::Session(format!("Failed to open nonce lock: {e}")))?
        };
        lock_file
            .lock_exclusive()
            .map_err(|e| FrostNetError::Session(format!("Failed to lock nonce store: {e}")))?;

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        // Whether this call is creating the store decides whether its directory
        // entry needs flushing below. Appends to an existing file are covered by
        // syncing the file itself; the very first record also creates a name,
        // and a name that never reaches the disk takes the whole store with it,
        // so every session id reads as unconsumed after the next boot. That is
        // the first session, not the hundred-thousandth, so it is the case that
        // matters most.
        let is_new = !self.path.exists();
        let mut file = opts
            .open(&self.path)
            .map_err(|e| FrostNetError::Session(format!("Failed to open nonce store: {e}")))?;

        let hex_id = hex::encode(session_id);
        let write_result = writeln!(file, "{hex_id}");
        let sync_result = if write_result.is_ok() {
            file.sync_all().and_then(|()| {
                if is_new {
                    keep_core::fsync_dir(&self.path)
                } else {
                    Ok(())
                }
            })
        } else {
            Ok(())
        };

        let _ = FileExt::unlock(&lock_file);

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
    let lock_path = path.with_extension("lock");
    let lock_file = {
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&lock_path)?
    };
    lock_file.lock_exclusive()?;

    let tmp_path = path.with_extension("tmp");

    let result = (|| {
        let mut file = {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&tmp_path)?
        };

        for entry in entries {
            writeln!(file, "{}", hex::encode(entry))?;
        }
        file.sync_all()?;

        std::fs::rename(&tmp_path, path)?;
        // The sync above makes the contents durable, not the name pointing at
        // them. Without this a power loss after the rename can restore the
        // previous file, which for a nonce store means a consumed nonce reads
        // as available again on the next boot.
        keep_core::fsync_dir(path)
    })();

    let _ = FileExt::unlock(&lock_file);
    result
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
    use std::time::Duration;
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

    /// A truncated entry must refuse to load, not be skipped.
    ///
    /// The lost record is the most recently consumed session, because a short
    /// entry is a partial append. Skipping it silently returned that session id
    /// to the available set, so the recovery path itself produced the replay
    /// this store exists to prevent, and the only signal was a warning nobody
    /// reads after a crash.
    #[test]
    fn a_truncated_entry_refuses_to_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces");

        // One good entry, then a short one: an append cut off mid-write that
        // still happens to decode as hex.
        std::fs::write(
            &path,
            format!("{}\n{}\n", hex::encode([7u8; 32]), hex::encode([9u8; 16])),
        )
        .unwrap();

        let err = match FileNonceStore::new(&path) {
            Err(e) => e,
            Ok(_) => panic!("a store that cannot be trusted must not load"),
        };
        assert!(
            format!("{err}").contains("truncated or corrupt"),
            "the refusal should say why the store is untrustworthy, got: {err}"
        );
    }

    /// The whole point of refusing: a session already consumed must not come
    /// back as available because the record after it was cut short.
    #[test]
    fn a_truncated_store_does_not_resurrect_a_consumed_session() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces");
        let consumed = [7u8; 32];

        std::fs::write(
            &path,
            format!("{}\n{}\n", hex::encode(consumed), hex::encode([9u8; 16])),
        )
        .unwrap();

        // Loading must fail rather than yield a store that answers "available"
        // for a session id the file says was consumed.
        assert!(
            FileNonceStore::new(&path).is_err(),
            "a store loaded past a truncated entry would report a consumed \
             session as available"
        );
    }

    /// The reader must take the same lock the writers take.
    ///
    /// It previously locked the store file while `record` and the rewrite path
    /// locked a sibling, so the two never contended and the reader's lock
    /// excluded nothing. Observable without threads: loading creates the lock
    /// file the writers use.
    #[test]
    #[cfg_attr(windows, ignore = "file locking behaves differently on Windows")]
    fn loading_takes_the_lock_the_writers_take() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces");
        std::fs::write(&path, format!("{}\n", hex::encode([1u8; 32]))).unwrap();

        // Assert the lock is HELD, not merely that the lock file exists: that
        // file is created by `open`, so an existence check stays green even if
        // the `lock_exclusive` call is deleted outright.
        //
        // flock follows the open file description, so a second handle on the
        // same path contends even within a single process.
        let held = {
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path.with_extension("lock"))
                .unwrap();
            f.lock_exclusive().unwrap();
            f
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let load_path = path.clone();
        let loader = std::thread::spawn(move || {
            let result = FileNonceStore::new(&load_path);
            tx.send(()).unwrap();
            result
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "loading must block while a writer holds the lock"
        );

        FileExt::unlock(&held).unwrap();

        let store = loader
            .join()
            .unwrap()
            .expect("loading must succeed once the lock is released");
        assert!(store.is_consumed(&[1u8; 32]), "the entry must be loaded");
    }
}
