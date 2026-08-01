// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceEntry {
    pub commitment: String,
    pub created_at: u64,
    pub used: bool,
    pub used_at: Option<u64>,
    pub session_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NonceStoreData {
    nonces: HashMap<String, Vec<NonceEntry>>,
}

pub struct NonceStore {
    path: PathBuf,
    data: NonceStoreData,
}

impl NonceStore {
    pub fn open(path: &Path) -> Result<Self> {
        let store_path = path.join("nonce_store.json");
        let data = if store_path.exists() {
            let content =
                std::fs::read_to_string(&store_path).context("Failed to read nonce store")?;
            serde_json::from_str(&content).context("Failed to parse nonce store")?
        } else {
            NonceStoreData::default()
        };
        Ok(Self {
            path: store_path,
            data,
        })
    }

    fn with_lock<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut NonceStoreData) -> Result<T>,
    {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create nonce store directory")?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .context("Failed to open nonce store")?;

        file.lock_exclusive()
            .context("Failed to acquire nonce store lock")?;

        let mut data = {
            let mut content = String::new();
            let mut reader = &file;
            reader
                .read_to_string(&mut content)
                .context("Failed to read nonce store")?;
            if content.is_empty() {
                NonceStoreData::default()
            } else {
                serde_json::from_str(&content).context("Failed to parse nonce store")?
            }
        };

        let result = f(&mut data)?;

        let content =
            serde_json::to_string_pretty(&data).context("Failed to serialize nonce store")?;
        Self::write_locked(&file, &content)?;

        self.data = data;

        FileExt::unlock(&file).context("Failed to release nonce store lock")?;

        Ok(result)
    }

    fn write_locked(file: &File, content: &str) -> Result<()> {
        file.set_len(0).context("Failed to truncate nonce store")?;
        let mut writer = file;
        use std::io::Seek;
        writer
            .seek(std::io::SeekFrom::Start(0))
            .context("Failed to seek nonce store")?;
        writer
            .write_all(content.as_bytes())
            .context("Failed to write nonce store")?;
        writer.flush().context("Failed to flush nonce store")?;
        Ok(())
    }

    pub fn add_nonce(&mut self, group: &str, commitment: &str) -> Result<()> {
        let group = group.to_string();
        let commitment = commitment.to_string();

        self.with_lock(|data| {
            let entries = data.nonces.entry(group).or_default();
            if entries.iter().any(|e| e.commitment == commitment) {
                return Ok(());
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            entries.push(NonceEntry {
                commitment,
                created_at: now,
                used: false,
                used_at: None,
                session_id: None,
            });
            Ok(())
        })
    }

    /// Claims a round-1 commitment for signing, reporting whether that is safe.
    ///
    /// Returns `false` if this commitment has been claimed before. That is the
    /// reuse: two signature shares over one nonce under different challenges
    /// give `s = (z1 - z2) / (c1 - c2)`, which is the signer's key share.
    ///
    /// Claiming marks the entry used **here**, when the commitment is handed to
    /// the signing path. Previously nothing did: the only writer of `used` was
    /// `mark_nonce_used`, which had no callers anywhere in the workspace, so no
    /// entry was ever `used`, the reject branch was unreachable, and a repeated
    /// commitment fell through to `Ok(true)` and got signed. The caller's
    /// "nonce has already been used - aborting to prevent key compromise" error
    /// could not fire. A guard whose reject depends on a second call that never
    /// happens is worse than no guard, because the call site reads as protected.
    ///
    /// Pre-committed nonces (`add_nonce`, the kind-21106 flow) are stored
    /// unused and are claimed here on first use, which is why this cannot simply
    /// reject on presence.
    pub fn check_and_add_nonce(&mut self, group: &str, commitment: &str) -> Result<bool> {
        let group = group.to_string();
        let commitment = commitment.to_string();

        self.with_lock(|data| {
            let entries = data.nonces.entry(group).or_default();

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if let Some(entry) = entries.iter_mut().find(|e| e.commitment == commitment) {
                if entry.used {
                    return Ok(false);
                }
                entry.used = true;
                entry.used_at = Some(now);
                return Ok(true);
            }

            entries.push(NonceEntry {
                commitment,
                created_at: now,
                used: true,
                used_at: Some(now),
                session_id: None,
            });
            Ok(true)
        })
    }

    #[allow(dead_code)]
    pub fn is_nonce_used(&self, group: &str, commitment: &str) -> bool {
        self.data
            .nonces
            .get(group)
            .map(|entries| entries.iter().any(|e| e.commitment == commitment && e.used))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn get_available_nonces(&self, group: &str) -> Vec<&NonceEntry> {
        self.data
            .nonces
            .get(group)
            .map(|entries| entries.iter().filter(|e| !e.used).collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn get_used_nonces(&self, group: &str) -> Vec<&NonceEntry> {
        self.data
            .nonces
            .get(group)
            .map(|entries| entries.iter().filter(|e| e.used).collect())
            .unwrap_or_default()
    }

    pub fn nonce_stats(&self, group: &str) -> (usize, usize) {
        self.data
            .nonces
            .get(group)
            .map(|entries| {
                let available = entries.iter().filter(|e| !e.used).count();
                let used = entries.iter().filter(|e| e.used).count();
                (available, used)
            })
            .unwrap_or((0, 0))
    }

    #[allow(dead_code)]
    pub fn clear_used_nonces(&mut self, group: &str) -> Result<usize> {
        let group = group.to_string();

        self.with_lock(|data| {
            let count = if let Some(entries) = data.nonces.get_mut(&group) {
                let before = entries.len();
                entries.retain(|e| !e.used);
                before - entries.len()
            } else {
                0
            };
            Ok(count)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &std::path::Path) -> NonceStore {
        NonceStore::open(&dir.join("nonces.json")).unwrap()
    }

    #[test]
    fn a_repeated_commitment_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        assert!(s.check_and_add_nonce("group", "aabb").unwrap(), "first use");
        assert!(
            !s.check_and_add_nonce("group", "aabb").unwrap(),
            "a second claim of the same commitment is nonce reuse and must be refused"
        );
        assert!(
            !s.check_and_add_nonce("group", "aabb").unwrap(),
            "and stays refused"
        );
    }

    #[test]
    fn a_precommitted_nonce_is_usable_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        // The kind-21106 flow registers commitments ahead of time, unused.
        s.add_nonce("group", "ccdd").unwrap();
        assert_eq!(s.nonce_stats("group"), (1, 0));

        assert!(
            s.check_and_add_nonce("group", "ccdd").unwrap(),
            "a pre-committed nonce must still be usable once"
        );
        assert_eq!(s.nonce_stats("group"), (0, 1), "claiming marks it used");
        assert!(
            !s.check_and_add_nonce("group", "ccdd").unwrap(),
            "but only once"
        );
    }

    #[test]
    fn groups_do_not_share_commitments() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        assert!(s.check_and_add_nonce("a", "eeff").unwrap());
        assert!(
            s.check_and_add_nonce("b", "eeff").unwrap(),
            "the same bytes under a different group are a different nonce"
        );
    }

    #[test]
    fn the_rejection_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store(dir.path())
            .check_and_add_nonce("group", "1234")
            .unwrap());
        assert!(
            !store(dir.path())
                .check_and_add_nonce("group", "1234")
                .unwrap(),
            "a reboot must not hand the nonce back"
        );
    }
}
