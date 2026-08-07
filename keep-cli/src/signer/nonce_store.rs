// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
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

/// Bumped when the meaning of an on-disk field changes.
///
/// A store written before the reject branch worked has `used: false` on
/// commitments that were in fact claimed and signed, indistinguishable from a
/// genuinely unused pre-committed nonce. Such a store would hand every legacy
/// entry back exactly once, in the one population that provably ran the broken
/// guard. Loading a versionless store therefore marks its entries claimed: the
/// cost is re-running the pre-commitment step, which is the fail-closed
/// direction.
const STORE_VERSION: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
struct NonceStoreData {
    #[serde(default)]
    version: u32,
    nonces: HashMap<String, Vec<NonceEntry>>,
}

impl NonceStoreData {
    fn migrate(&mut self) {
        if self.version >= STORE_VERSION {
            return;
        }
        for entries in self.nonces.values_mut() {
            for entry in entries.iter_mut() {
                entry.used = true;
                if entry.used_at.is_none() {
                    entry.used_at = Some(entry.created_at);
                }
            }
        }
        self.version = STORE_VERSION;
    }
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
            let mut parsed: NonceStoreData =
                serde_json::from_str(&content).context("Failed to parse nonce store")?;
            parsed.migrate();
            parsed
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
                NonceStoreData {
                    version: STORE_VERSION,
                    ..Default::default()
                }
            } else {
                let mut parsed: NonceStoreData =
                    serde_json::from_str(&content).context("Failed to parse nonce store")?;
                parsed.migrate();
                parsed
            }
        };

        let result = f(&mut data)?;

        let content =
            serde_json::to_string_pretty(&data).context("Failed to serialize nonce store")?;
        Self::write_locked(&self.path, &content)?;

        self.data = data;

        FileExt::unlock(&file).context("Failed to release nonce store lock")?;

        Ok(result)
    }

    /// Writes via a temporary file, fsync, then rename.
    ///
    /// Both halves matter for a replay guard. `File::flush` is a no-op, so the
    /// previous truncate-seek-write left a claim record in the page cache only:
    /// power loss between claiming a nonce and signing with it lost the record,
    /// which is exactly the reboot-replay case this store exists to stop. And
    /// truncating in place meant a crash mid-write left partial JSON, after
    /// which every later run fails to parse and the obvious fix is to delete
    /// the file, taking all replay protection with it. A rename is atomic, so
    /// the store is always either the old contents or the new ones.
    fn write_locked(path: &Path, content: &str) -> Result<()> {
        let tmp_path = path.with_extension("tmp");
        let mut tmp = {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&tmp_path)
                .context("Failed to open nonce store temp file")?
        };
        tmp.write_all(content.as_bytes())
            .context("Failed to write nonce store")?;
        tmp.sync_all().context("Failed to fsync nonce store")?;
        drop(tmp);
        std::fs::rename(&tmp_path, path).context("Failed to replace nonce store")?;
        // Syncing the temp file above makes its contents durable; it does not
        // make the name pointing at them durable. Without this a power loss
        // after the rename can leave the previous store in place, which is a
        // claimed nonce silently becoming unclaimed: exactly the reboot replay
        // this store exists to stop, and the case the file sync was added for.
        keep_core::fsync_dir(path).context("Failed to fsync nonce store directory")?;
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
    pub fn check_and_add_nonce(
        &mut self,
        group: &str,
        commitment: &str,
        session_id: Option<&str>,
    ) -> Result<bool> {
        let group = group.to_string();
        let commitment = commitment.to_string();
        let session_id = session_id.map(String::from);

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
                entry.session_id = session_id;
                return Ok(true);
            }

            entries.push(NonceEntry {
                commitment,
                created_at: now,
                used: true,
                used_at: Some(now),
                session_id,
            });
            Ok(true)
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // `open` joins the file name onto its argument, so this takes the directory.
    fn store(dir: &std::path::Path) -> NonceStore {
        NonceStore::open(dir).unwrap()
    }

    #[test]
    fn a_repeated_commitment_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        assert!(
            s.check_and_add_nonce("group", "aabb", None).unwrap(),
            "first use"
        );
        assert!(
            !s.check_and_add_nonce("group", "aabb", None).unwrap(),
            "a second claim of the same commitment is nonce reuse and must be refused"
        );
        assert!(
            !s.check_and_add_nonce("group", "aabb", None).unwrap(),
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
            s.check_and_add_nonce("group", "ccdd", None).unwrap(),
            "a pre-committed nonce must still be usable once"
        );
        assert_eq!(s.nonce_stats("group"), (0, 1), "claiming marks it used");
        assert!(
            !s.check_and_add_nonce("group", "ccdd", None).unwrap(),
            "but only once"
        );
    }

    #[test]
    fn a_second_live_handle_cannot_re_hand_the_nonce() {
        let dir = tempfile::tempdir().unwrap();
        // `b` is opened before `a` claims, so its in-memory snapshot is stale.
        // The reject has to come from the re-read under the flock, not from
        // whatever the handle happened to load at open time.
        let (mut a, mut b) = (store(dir.path()), store(dir.path()));

        assert!(a.check_and_add_nonce("g", "7788", None).unwrap());
        assert!(
            !b.check_and_add_nonce("g", "7788", None).unwrap(),
            "a concurrently-open handle must not hand the nonce out again"
        );
    }

    #[test]
    fn re_registering_a_claimed_nonce_does_not_resurrect_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        assert!(s.check_and_add_nonce("group", "99aa", None).unwrap());
        // Re-running the pre-commitment loop must not reset the entry.
        s.add_nonce("group", "99aa").unwrap();
        assert_eq!(s.nonce_stats("group"), (0, 1));
        assert!(
            !s.check_and_add_nonce("group", "99aa", None).unwrap(),
            "a claimed nonce stays claimed after add_nonce sees it again"
        );
    }

    #[test]
    fn a_legacy_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        // A store written before the reject branch worked: no version, and
        // entries that were claimed and signed still recorded as unused.
        std::fs::write(
            dir.path().join("nonce_store.json"),
            r#"{"nonces":{"group":[{"commitment":"bbcc","created_at":1,"used":false,"used_at":null,"session_id":null}]}}"#,
        )
        .unwrap();

        assert!(
            !store(dir.path())
                .check_and_add_nonce("group", "bbcc", None)
                .unwrap(),
            "entries from a store that ran the broken guard must not get one free reuse"
        );
    }

    #[test]
    fn the_session_that_burned_a_nonce_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        assert!(s
            .check_and_add_nonce("group", "ddee", Some("sess-1"))
            .unwrap());
        let entry = s.data.nonces["group"]
            .iter()
            .find(|e| e.commitment == "ddee")
            .unwrap();
        assert_eq!(entry.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn groups_do_not_share_commitments() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());

        assert!(s.check_and_add_nonce("a", "eeff", None).unwrap());
        assert!(
            s.check_and_add_nonce("b", "eeff", None).unwrap(),
            "the same bytes under a different group are a different nonce"
        );
    }

    #[test]
    fn the_rejection_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store(dir.path())
            .check_and_add_nonce("group", "1234", None)
            .unwrap());
        assert!(
            !store(dir.path())
                .check_and_add_nonce("group", "1234", None)
                .unwrap(),
            "a reboot must not hand the nonce back"
        );
    }

    /// A claim that cannot be made durable must not be reported as made.
    ///
    /// I had written that this change was untestable because crash durability
    /// needs fault injection. That is true of the crash, and it is not true of
    /// the property that matters here: the caller signs on `Ok(true)`, so a
    /// directory sync that fails has to fail the claim rather than be swallowed.
    /// An unreadable directory produces exactly that failure without simulating
    /// anything, because opening the directory to sync it is what breaks.
    ///
    /// Unix only, and skipped as root, where the mode is not enforced.
    #[cfg(unix)]
    #[test]
    fn a_claim_that_cannot_be_synced_is_not_reported_as_claimed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        // Establish the store while the directory is still readable.
        assert!(s.check_and_add_nonce("group", "aabb", None).unwrap());

        // Write and search, but not read: the rename still succeeds, opening
        // the directory to sync it does not.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o300)).unwrap();
        // Root ignores the mode, and so do some filesystems. Check that the
        // restriction actually took rather than asserting into a setup that
        // never applied, which would pass whatever the code did.
        if std::fs::File::open(dir.path()).is_ok() {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let result = s.check_and_add_nonce("group", "ccdd", None);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "a claim whose record cannot be made durable must not return success, \
             or the caller signs against a claim that may not survive a reboot"
        );
    }
}
