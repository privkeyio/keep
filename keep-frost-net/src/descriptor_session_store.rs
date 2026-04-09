// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, warn};

use crate::descriptor_session::{DescriptorSessionStore, PersistedDescriptorSession};
use crate::error::{FrostNetError, Result};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("descriptor_sessions");

pub struct FileDescriptorSessionStore {
    db: Database,
}

impl FileDescriptorSessionStore {
    pub fn new(path: &Path) -> Result<Self> {
        let db = Database::create(path)
            .map_err(|e| FrostNetError::Session(format!("Failed to open session store: {e}")))?;

        let txn = db.begin_write().map_err(|e| {
            FrostNetError::Session(format!("Failed to begin write for table creation: {e}"))
        })?;
        txn.open_table(TABLE)
            .map_err(|e| FrostNetError::Session(format!("Failed to create sessions table: {e}")))?;
        txn.commit()
            .map_err(|e| FrostNetError::Session(format!("Failed to commit table creation: {e}")))?;

        debug!(path = ?path, "Opened descriptor session store");
        Ok(Self { db })
    }
}

impl DescriptorSessionStore for FileDescriptorSessionStore {
    fn save(&self, session: &PersistedDescriptorSession) -> Result<()> {
        let json = serde_json::to_vec(session)?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| FrostNetError::Session(format!("Failed to begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| FrostNetError::Session(format!("Failed to open table: {e}")))?;
            table
                .insert(session.session_id.as_slice(), json.as_slice())
                .map_err(|e| FrostNetError::Session(format!("Failed to insert session: {e}")))?;
        }
        txn.commit()
            .map_err(|e| FrostNetError::Session(format!("Failed to commit session: {e}")))?;
        Ok(())
    }

    fn load(&self, session_id: &[u8; 32]) -> Result<Option<PersistedDescriptorSession>> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| FrostNetError::Session(format!("Failed to begin read: {e}")))?;
        let table = txn
            .open_table(TABLE)
            .map_err(|e| FrostNetError::Session(format!("Failed to open table: {e}")))?;
        let entry = table
            .get(session_id.as_slice())
            .map_err(|e| FrostNetError::Session(format!("Failed to get session: {e}")))?;
        entry
            .map(|data| serde_json::from_slice(data.value()))
            .transpose()
            .map_err(Into::into)
    }

    fn load_all(&self) -> Result<Vec<PersistedDescriptorSession>> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| FrostNetError::Session(format!("Failed to begin read: {e}")))?;
        let table = txn
            .open_table(TABLE)
            .map_err(|e| FrostNetError::Session(format!("Failed to open table: {e}")))?;
        let mut sessions = Vec::new();
        let mut corrupt_keys = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| FrostNetError::Session(format!("Failed to iterate sessions: {e}")))?;
        for entry in iter {
            let (key, value) = entry.map_err(|e| {
                FrostNetError::Session(format!("Failed to read session entry: {e}"))
            })?;
            match serde_json::from_slice::<PersistedDescriptorSession>(value.value()) {
                Ok(session) => sessions.push(session),
                Err(e) => {
                    warn!("Removing corrupt session entry: {e}");
                    corrupt_keys.push(key.value().to_vec());
                }
            }
        }
        drop(txn);

        if !corrupt_keys.is_empty() {
            if let Ok(txn) = self.db.begin_write() {
                if let Ok(mut table) = txn.open_table(TABLE) {
                    for key in &corrupt_keys {
                        let _ = table.remove(key.as_slice());
                    }
                }
                let _ = txn.commit();
            }
        }

        Ok(sessions)
    }

    fn delete(&self, session_id: &[u8; 32]) -> Result<()> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| FrostNetError::Session(format!("Failed to begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| FrostNetError::Session(format!("Failed to open table: {e}")))?;
            table
                .remove(session_id.as_slice())
                .map_err(|e| FrostNetError::Session(format!("Failed to delete session: {e}")))?;
        }
        txn.commit()
            .map_err(|e| FrostNetError::Session(format!("Failed to commit delete: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor_session::PersistedSessionState;
    use crate::protocol::{KeySlot, PolicyTier, WalletPolicy};
    use std::collections::{BTreeMap, HashSet};
    use tempfile::tempdir;

    fn test_persisted_session(id: [u8; 32]) -> PersistedDescriptorSession {
        PersistedDescriptorSession {
            session_id: id,
            group_pubkey: [2u8; 32],
            policy: WalletPolicy {
                recovery_tiers: vec![PolicyTier {
                    threshold: 2,
                    key_slots: vec![
                        KeySlot::Participant { share_index: 1 },
                        KeySlot::Participant { share_index: 2 },
                    ],
                    timelock_months: 6,
                }],
            },
            network: "signet".into(),
            initiator: None,
            contributions: BTreeMap::new(),
            expected_contributors: [1u16, 2].into_iter().collect(),
            descriptor: None,
            acks: HashSet::new(),
            nacks: HashSet::new(),
            expected_acks: [1u16, 2].into_iter().collect(),
            state: PersistedSessionState::Proposed,
            created_at_unix: 1700000000,
            contributions_complete_at_unix: None,
            finalized_at_unix: None,
            timeout_secs: 600,
            contribution_timeout_secs: 300,
            finalize_timeout_secs: 300,
            ack_phase_timeout_secs: 300,
        }
    }

    #[test]
    fn test_file_store_crud() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.redb");
        let store = FileDescriptorSessionStore::new(&path).unwrap();

        let session = test_persisted_session([1u8; 32]);
        store.save(&session).unwrap();

        let loaded = store.load(&[1u8; 32]).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.session_id, [1u8; 32]);
        assert_eq!(loaded.network, "signet");

        assert!(store.load(&[99u8; 32]).unwrap().is_none());

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);

        store.delete(&[1u8; 32]).unwrap();
        assert!(store.load(&[1u8; 32]).unwrap().is_none());
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn test_file_store_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.redb");

        {
            let store = FileDescriptorSessionStore::new(&path).unwrap();
            store.save(&test_persisted_session([1u8; 32])).unwrap();
            store.save(&test_persisted_session([2u8; 32])).unwrap();
        }

        {
            let store = FileDescriptorSessionStore::new(&path).unwrap();
            let all = store.load_all().unwrap();
            assert_eq!(all.len(), 2);
            assert!(store.load(&[1u8; 32]).unwrap().is_some());
            assert!(store.load(&[2u8; 32]).unwrap().is_some());
        }
    }

    #[test]
    fn test_file_store_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.redb");
        let store = FileDescriptorSessionStore::new(&path).unwrap();

        let mut session = test_persisted_session([1u8; 32]);
        store.save(&session).unwrap();

        session.state = PersistedSessionState::Finalized;
        store.save(&session).unwrap();

        let loaded = store.load(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(loaded.state, PersistedSessionState::Finalized);

        assert_eq!(store.load_all().unwrap().len(), 1);
    }
}
