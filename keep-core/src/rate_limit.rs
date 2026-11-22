// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U8;
use blake2::digest::{KeyInit, Mac};
use blake2::Blake2bMac;
use fs4::FileExt;
use subtle::ConstantTimeEq;

use crate::error::{KeepError, StorageError};

const MAX_ATTEMPTS: u32 = 5;
const BASE_DELAY_SECS: u64 = 1;
const MAX_DELAY_SECS: u64 = 300;
const RECORD_SIZE: usize = 48;
const OLD_RECORD_SIZE: usize = 20;

fn rate_limit_path(storage_path: &Path) -> PathBuf {
    if storage_path.is_dir() {
        storage_path.join(".ratelimit")
    } else {
        let parent = storage_path.parent().unwrap_or(Path::new("."));
        let name = storage_path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        parent.join(format!(".{name}.ratelimit"))
    }
}

fn trip_log_path(storage_path: &Path) -> PathBuf {
    let mut rl = rate_limit_path(storage_path);
    let new_name = match rl.file_name() {
        Some(n) => format!("{}.trips", n.to_string_lossy()),
        None => ".ratelimit.trips".to_string(),
    };
    rl.set_file_name(new_name);
    rl
}

pub(crate) fn derive_hmac_key(salt: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    hasher.update(b"keep.privkey.io/v1/rate-limit/hmac-key-derivation");
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

type Blake2bMac64 = Blake2bMac<U8>;

fn compute_hmac(data: &[u8], key: &[u8; 32]) -> [u8; 8] {
    let mut mac = <Blake2bMac64 as KeyInit>::new_from_slice(key).expect("valid key length");
    mac.update(data);
    let result = mac.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&result.into_bytes());
    tag
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// Attempts are numbered within an epoch: `counted` only grows, and a success
// raises `cleared` to its own number. The live count is the difference, so
// successes finishing in any order clear only what was counted up to them.
// Once nothing is outstanding the record is emptied, leaving no count or time
// behind, and the next attempt starts a new random epoch, so a success still
// holding the old one clears nothing.
struct RateLimitRecord {
    epoch: [u8; 8],
    counted: u64,
    cleared: u64,
    last_attempt: u64,
    // The last attempt this cycle's trip covers; a cycle ends when `cleared`
    // reaches it.
    tripped: u64,
}

impl RateLimitRecord {
    fn new() -> Self {
        Self {
            epoch: [0; 8],
            counted: 0,
            cleared: 0,
            last_attempt: 0,
            tripped: 0,
        }
    }

    fn live(&self) -> u32 {
        u32::try_from(self.counted.saturating_sub(self.cleared)).unwrap_or(u32::MAX)
    }

    fn to_bytes(&self, hmac_key: &[u8; 32]) -> [u8; RECORD_SIZE] {
        let mut data = [0u8; RECORD_SIZE];
        data[0..8].copy_from_slice(&self.epoch);
        data[8..16].copy_from_slice(&self.counted.to_le_bytes());
        data[16..24].copy_from_slice(&self.cleared.to_le_bytes());
        data[24..32].copy_from_slice(&self.last_attempt.to_le_bytes());
        data[32..40].copy_from_slice(&self.tripped.to_le_bytes());
        let tag = compute_hmac(&data[0..40], hmac_key);
        data[40..48].copy_from_slice(&tag);
        data
    }

    fn from_bytes(data: &[u8], hmac_key: &[u8; 32]) -> Option<Self> {
        let u64_at = |i: usize| data[i..i + 8].try_into().ok().map(u64::from_le_bytes);
        match data.len() {
            RECORD_SIZE => {
                let tag = compute_hmac(&data[0..40], hmac_key);
                if !bool::from(data[40..48].ct_eq(&tag)) {
                    return None;
                }
                Some(Self {
                    epoch: data[0..8].try_into().ok()?,
                    counted: u64_at(8)?,
                    cleared: u64_at(16)?,
                    last_attempt: u64_at(24)?,
                    tripped: u64_at(32)?,
                })
            }
            // Written by an earlier release, whose failures queued their own
            // trip on reaching the limit.
            OLD_RECORD_SIZE => {
                let tag = compute_hmac(&data[0..12], hmac_key);
                if !bool::from(data[12..20].ct_eq(&tag)) {
                    return None;
                }
                let counted = u64::from(u32::from_le_bytes(data[0..4].try_into().ok()?));
                Some(Self {
                    epoch: [0; 8],
                    counted,
                    cleared: 0,
                    last_attempt: u64_at(4)?,
                    tripped: if counted >= u64::from(MAX_ATTEMPTS) {
                        counted
                    } else {
                        0
                    },
                })
            }
            _ => None,
        }
    }

    fn delay_duration(&self) -> Duration {
        let live = self.live();
        if live < MAX_ATTEMPTS {
            return Duration::ZERO;
        }
        let excess = live - MAX_ATTEMPTS;
        let delay_secs = BASE_DELAY_SECS.saturating_mul(1u64 << excess.min(8));
        Duration::from_secs(delay_secs.min(MAX_DELAY_SECS))
    }

    fn remaining_delay(&self) -> Duration {
        if self.last_attempt == 0 {
            return Duration::ZERO;
        }
        let elapsed = now_secs().saturating_sub(self.last_attempt);
        let required = self.delay_duration().as_secs();
        Duration::from_secs(required.saturating_sub(elapsed))
    }
}

/// A short or unauthenticated record reads as new, but a failed read is an
/// error: treating it as new would reset an active delay.
fn read_record_from_file(file: &mut File, hmac_key: &[u8; 32]) -> std::io::Result<RateLimitRecord> {
    let mut data = Vec::with_capacity(RECORD_SIZE);
    Read::by_ref(file)
        .take(RECORD_SIZE as u64)
        .read_to_end(&mut data)?;
    Ok(RateLimitRecord::from_bytes(&data, hmac_key).unwrap_or_else(RateLimitRecord::new))
}

/// An attempt's place in the record, for `record_success`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    epoch: [u8; 8],
    number: u64,
}

/// Count an unlock attempt before its password is tried, or refuse it.
///
/// Refuses while the record says to wait, and when the record cannot be
/// opened, locked, written or synced: an attempt that is not on disk before
/// the password check could go uncounted, through a full disk, a crash during
/// key derivation, or several attempts reading the same count at once. A
/// success then clears the attempts counted up to its own, so only attempts
/// that did not succeed stay counted.
pub(crate) fn count_attempt(path: &Path, hmac_key: &[u8; 32]) -> Result<Attempt, KeepError> {
    let rl_path = rate_limit_path(path);
    let unusable = |e: std::io::Error| {
        tracing::error!(error = %e, path = %rl_path.display(), "the unlock rate limit cannot be used, refusing the attempt");
        KeepError::StorageErr(StorageError::io(format!(
            "the unlock attempt counter {} cannot be used ({e}). It must be a file this user can read and write",
            rl_path.display()
        )))
    };

    let mut file = open_rate_limit_file(&rl_path).map_err(unusable)?;
    FileExt::lock(&file).map_err(unusable)?;

    let mut record = read_record_from_file(&mut file, hmac_key).map_err(unusable)?;
    let remaining = record.remaining_delay();
    if remaining > Duration::ZERO {
        return Err(KeepError::RateLimited(remaining.as_secs().max(1)));
    }

    let (prior, prior_time, prior_counted) = (record.live(), record.last_attempt, record.counted);
    if prior_counted == 0 {
        record.epoch = crate::crypto::try_random_bytes()?;
    }
    record.counted = record.counted.saturating_add(1);
    record.last_attempt = now_secs();
    // `prior` attempts are on disk with no success after them. The first
    // attempt past the limit in a cycle queues the trip, under the lock, so it
    // is recorded once and cannot be skipped by abandoning an attempt. It
    // covers the attempts before this one, so a success that clears them all
    // lets the next group trip.
    let trips = prior >= MAX_ATTEMPTS && record.tripped <= record.cleared;
    if trips {
        record.tripped = prior_counted;
    }
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&record.to_bytes(hmac_key)))
        .and_then(|()| file.sync_all())
        .map_err(unusable)?;
    if prior_counted == 0 {
        crate::rotation::fsync_dir(&rl_path).map_err(unusable)?;
    }

    if trips {
        record_trip(path, hmac_key, prior, prior_time);
    }
    Ok(Attempt {
        epoch: record.epoch,
        number: record.counted,
    })
}

fn open_rate_limit_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    private_no_follow(&mut opts);
    opts.open(path)
}

// Owner-only, and never through a link: the record's path is fixed inside the
// vault folder, and a link planted there would have its target overwritten.
fn private_no_follow(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = opts;
}

/// After `attempt` succeeded, clear it and every attempt numbered before it,
/// under the record's lock. Attempts numbered after it stay counted, whatever
/// order successes finish in. When that leaves nothing outstanding, the record
/// is emptied, so a successful unlock leaves no count or time behind. The
/// record is changed in place, never removed, so an attempt that opened it
/// first counts where later ones look.
pub(crate) fn record_success(path: &Path, hmac_key: &[u8; 32], attempt: Attempt) {
    let rl_path = rate_limit_path(path);
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    private_no_follow(&mut opts);
    let Ok(mut file) = opts.open(&rl_path) else {
        return;
    };
    let reset = FileExt::lock(&file).and_then(|()| {
        let mut record = read_record_from_file(&mut file, hmac_key)?;
        if record.epoch != attempt.epoch || record.counted == 0 {
            return Ok(());
        }
        record.cleared = record.cleared.max(attempt.number.min(record.counted));
        if record.live() == 0 {
            file.set_len(0)?;
        } else {
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&record.to_bytes(hmac_key))?;
        }
        file.sync_all()
    });
    if let Err(e) = reset {
        tracing::error!(error = %e, "the unlock rate limit could not be reset");
    }
}

/// Clear every attempt on the record.
#[cfg(test)]
pub(crate) fn reset_for_tests(path: &Path, hmac_key: &[u8; 32]) {
    let Ok(mut file) = File::open(rate_limit_path(path)) else {
        return;
    };
    let record = read_record_from_file(&mut file, hmac_key).unwrap();
    drop(file);
    let all = Attempt {
        epoch: record.epoch,
        number: u64::MAX,
    };
    record_success(path, hmac_key, all);
}

/// A persisted rate-limit trip event awaiting flush to the audit log.
///
/// Records are authenticated with an HMAC key derived from the PUBLIC header
/// salt, so they are tamper-evident against corruption but NOT forgery by an
/// attacker with read access to the vault directory. Trip audit events are
/// therefore best-effort and sit outside the password-keyed audit chain's
/// cryptographic tamper-evidence boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingTrip {
    pub failed_attempts: u32,
    pub timestamp: u64,
}

const TRIP_RECORD_SIZE: usize = 20;
const MAX_TRIP_RECORDS: usize = 256;

impl PendingTrip {
    /// The time to give this trip's audit entry: its recorded time, but
    /// never later than now. The trip file is forgeable (see above), and an
    /// entry dated in the future would pass for the latest thing the log
    /// recorded.
    pub(crate) fn audit_time(&self) -> i64 {
        i64::try_from(self.timestamp)
            .unwrap_or(i64::MAX)
            .min(chrono::Utc::now().timestamp())
    }

    fn to_bytes(&self, hmac_key: &[u8; 32]) -> [u8; TRIP_RECORD_SIZE] {
        let mut data = [0u8; TRIP_RECORD_SIZE];
        data[0..4].copy_from_slice(&self.failed_attempts.to_le_bytes());
        data[4..12].copy_from_slice(&self.timestamp.to_le_bytes());
        let tag = compute_hmac(&data[0..12], hmac_key);
        data[12..20].copy_from_slice(&tag);
        data
    }

    fn from_bytes(data: &[u8], hmac_key: &[u8; 32]) -> Option<Self> {
        if data.len() != TRIP_RECORD_SIZE {
            return None;
        }
        let tag = compute_hmac(&data[0..12], hmac_key);
        if !bool::from(data[12..20].ct_eq(&tag)) {
            return None;
        }
        Some(Self {
            failed_attempts: u32::from_le_bytes(data[0..4].try_into().ok()?),
            timestamp: u64::from_le_bytes(data[4..12].try_into().ok()?),
        })
    }
}

fn record_trip(path: &Path, hmac_key: &[u8; 32], failed_attempts: u32, timestamp: u64) {
    let trip_path = trip_log_path(path);

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).append(true).create(true);
    private_no_follow(&mut opts);
    let Ok(file) = opts.open(&trip_path) else {
        return;
    };

    if FileExt::lock(&file).is_err() {
        return;
    }

    // Cap the file at MAX_TRIP_RECORDS to bound disk usage when nothing
    // flushes (e.g. hidden-volume unlock paths that don't open an audit log).
    if let Ok(meta) = file.metadata() {
        if meta.len() as usize >= TRIP_RECORD_SIZE * MAX_TRIP_RECORDS {
            tracing::warn!("rate-limit trip log at capacity; dropping trip event");
            return;
        }
    }

    let trip = PendingTrip {
        failed_attempts,
        timestamp,
    };
    let mut file = file;
    if file.write_all(&trip.to_bytes(hmac_key)).is_err() {
        tracing::debug!("failed to write rate-limit trip event");
    }
    let _ = file.sync_all();
}

/// Set the record to `failed_attempts`, the last one now.
#[cfg(test)]
pub(crate) fn set_attempts_for_tests(path: &Path, hmac_key: &[u8; 32], failed_attempts: u32) {
    let record = RateLimitRecord {
        epoch: [1; 8],
        counted: u64::from(failed_attempts),
        cleared: 0,
        tripped: 0,
        last_attempt: now_secs(),
    };
    fs::write(rate_limit_path(path), record.to_bytes(hmac_key)).unwrap();
}

/// Let the current back-off run out, keeping the count, as waiting would.
#[cfg(test)]
pub(crate) fn expire_delay_for_tests(path: &Path, hmac_key: &[u8; 32]) {
    let mut file = File::open(rate_limit_path(path)).unwrap();
    let mut record = read_record_from_file(&mut file, hmac_key).unwrap();
    record.last_attempt = 0;
    fs::write(rate_limit_path(path), record.to_bytes(hmac_key)).unwrap();
}

/// Write a trip record with any `timestamp`, as someone who can write the
/// vault folder can.
#[cfg(test)]
pub(crate) fn forge_trip_for_tests(path: &Path, hmac_key: &[u8; 32], timestamp: u64) {
    record_trip(path, hmac_key, 5, timestamp);
}

/// Read and clear all pending trip events for `path`. Records with invalid
/// HMAC tags are silently skipped (cannot be attributed to a real trip).
///
/// The read and the clear both happen under the exclusive lock so the drain is
/// atomic: a concurrent unlock cannot double-read, and a trip appended after
/// this returns is preserved. As with [`PendingTrip`], the HMAC key is derived
/// from the public salt, so this guards against corruption, not forgery.
pub(crate) fn drain_pending_trips(path: &Path, hmac_key: &[u8; 32]) -> Vec<PendingTrip> {
    let trip_path = trip_log_path(path);

    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    private_no_follow(&mut opts);
    let Ok(mut file) = opts.open(&trip_path) else {
        return Vec::new();
    };

    if FileExt::lock(&file).is_err() {
        return Vec::new();
    }

    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(buf.len() / TRIP_RECORD_SIZE);
    for chunk in buf.as_chunks::<TRIP_RECORD_SIZE>().0 {
        if let Some(trip) = PendingTrip::from_bytes(chunk, hmac_key) {
            out.push(trip);
        }
    }

    // Truncate while still holding the lock so the drain is atomic; the file is
    // left empty rather than removed (a later record_trip re-appends to it).
    let _ = file.set_len(0);
    drop(file);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    // Known answers from Python's hashlib BLAKE2b.
    #[test]
    fn hmac_key_and_tag_match_an_independent_implementation() {
        let salt: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(derive_hmac_key(&salt)),
            "170ad355c0c6457a42ef7ef5ed9ec6703feb5ab983dd6c4ca94d873df2e98d67"
        );
        assert_eq!(
            hex::encode(compute_hmac(b"keep known-answer", &[0x42; 32])),
            "cc19d17628dc0740"
        );
    }

    #[test]
    fn test_no_delay_on_first_attempts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..MAX_ATTEMPTS {
            fail(&path);
        }
    }

    #[test]
    fn test_delay_after_max_attempts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..MAX_ATTEMPTS {
            fail(&path);
        }
        assert_eq!(attempts(&path), MAX_ATTEMPTS);

        // Past the 1s step, so a second boundary cannot end the wait.
        set_attempts_for_tests(&path, &TEST_KEY, MAX_ATTEMPTS + 2);
        assert!(matches!(
            count_attempt(&path, &TEST_KEY),
            Err(KeepError::RateLimited(secs)) if secs >= BASE_DELAY_SECS
        ));
        assert_eq!(
            attempts(&path),
            MAX_ATTEMPTS + 2,
            "a refused attempt is not counted"
        );
    }

    #[test]
    fn test_exponential_backoff() {
        let mut record = RateLimitRecord::new();

        for _ in 0..(MAX_ATTEMPTS - 1) {
            record.counted += 1;
        }
        assert_eq!(record.delay_duration(), Duration::ZERO);

        record.counted += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(1));

        record.counted += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(2));

        record.counted += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(4));

        record.counted += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(8));
    }

    #[test]
    fn test_max_delay_cap() {
        let mut record = RateLimitRecord::new();
        record.counted = 50;
        assert!(record.delay_duration().as_secs() <= MAX_DELAY_SECS);
    }

    #[test]
    fn test_success_resets() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..MAX_ATTEMPTS + 2 {
            fail(&path);
        }

        reset_for_tests(&path, &TEST_KEY);
        assert!(count_attempt(&path, &TEST_KEY).is_ok());
    }

    #[test]
    fn test_persists_across_reads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        set_attempts_for_tests(&path, &TEST_KEY, MAX_ATTEMPTS + 2);
        assert!(count_attempt(&path, &TEST_KEY).is_err());
        assert!(count_attempt(&path, &TEST_KEY).is_err());
    }

    // A wrong password, as an unlock sees it.
    fn fail(path: &Path) {
        let _ = count_attempt(path, &TEST_KEY);
    }

    fn attempts(path: &Path) -> u32 {
        let mut file = File::open(rate_limit_path(path)).unwrap();
        read_record_from_file(&mut file, &TEST_KEY).unwrap().live()
    }

    // Five attempts on disk, the back-off over, and a sixth started: the
    // point at which the limiter has tripped.
    fn trip(path: &Path) {
        for _ in 0..MAX_ATTEMPTS {
            assert!(count_attempt(path, &TEST_KEY).is_ok());
        }
        expire_delay_for_tests(path, &TEST_KEY);
        assert!(count_attempt(path, &TEST_KEY).is_ok());
    }

    // Attempts whose outcome never came back, as after a crash during key
    // derivation, still count.
    #[test]
    fn an_attempt_counts_before_its_password_is_tried() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for n in 1..=MAX_ATTEMPTS {
            assert!(count_attempt(&path, &TEST_KEY).is_ok());
            assert_eq!(attempts(&path), n);
        }

        reset_for_tests(&path, &TEST_KEY);
        assert_eq!(attempts(&path), 0);
        assert!(count_attempt(&path, &TEST_KEY).is_ok());
        assert_eq!(attempts(&path), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_record_is_refused_and_its_target_left_alone() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();
        let target = dir.path().join("other");
        fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, path.join(".ratelimit")).unwrap();

        assert!(matches!(
            count_attempt(&path, &TEST_KEY),
            Err(KeepError::StorageErr(StorageError::Io { .. }))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"keep me");

        std::os::unix::fs::symlink(&target, trip_log_path(&path)).unwrap();
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    // Root ignores the permission bits these tests rely on.
    #[cfg(unix)]
    fn permissions_apply(dir: &Path) -> bool {
        let applies = File::create(dir.join(".probe")).is_err();
        if !applies {
            eprintln!(
                "permission bits are not enforced for this user, skipping the refusal checks"
            );
        }
        applies
    }

    // An attempt that could not be counted is refused, whether the folder
    // cannot take a new record or the record cannot be written.
    #[cfg(unix)]
    #[test]
    fn an_attempt_that_cannot_be_counted_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        if permissions_apply(&path) {
            assert!(matches!(
                count_attempt(&path, &TEST_KEY),
                Err(KeepError::StorageErr(StorageError::Io { .. }))
            ));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        fail(&path);
        let record = path.join(".ratelimit");
        fs::set_permissions(&record, fs::Permissions::from_mode(0o400)).unwrap();
        if OpenOptions::new().write(true).open(&record).is_err() {
            assert!(matches!(
                count_attempt(&path, &TEST_KEY),
                Err(KeepError::StorageErr(StorageError::Io { .. }))
            ));
        }
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(count_attempt(&path, &TEST_KEY).is_ok());
    }

    #[test]
    fn a_record_that_cannot_be_read_is_an_error_not_a_new_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();
        set_attempts_for_tests(&path, &TEST_KEY, MAX_ATTEMPTS + 2);

        let mut write_only = OpenOptions::new()
            .write(true)
            .open(rate_limit_path(&path))
            .unwrap();
        assert!(read_record_from_file(&mut write_only, &TEST_KEY).is_err());

        fs::write(rate_limit_path(&path), [0u8; 3]).unwrap();
        let mut short = File::open(rate_limit_path(&path)).unwrap();
        assert_eq!(
            read_record_from_file(&mut short, &TEST_KEY).unwrap().live(),
            0
        );
    }

    // An attempt that opened the record before a reset counts on the record
    // every later attempt reads, not on a detached copy.
    #[test]
    fn a_reset_keeps_the_record_an_earlier_open_sees() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();
        set_attempts_for_tests(&path, &TEST_KEY, 3);

        let mut opened_before = File::open(rate_limit_path(&path)).unwrap();
        reset_for_tests(&path, &TEST_KEY);
        assert_eq!(
            read_record_from_file(&mut opened_before, &TEST_KEY)
                .unwrap()
                .live(),
            0
        );
    }

    // A success clears what was counted up to it, not an attempt counted after
    // it that is still running.
    #[test]
    fn a_success_keeps_attempts_counted_after_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        fail(&path);
        let mine = count_attempt(&path, &TEST_KEY).unwrap();
        let later = count_attempt(&path, &TEST_KEY).unwrap();
        assert_eq!((mine.number, later.number), (2, 3));

        record_success(&path, &TEST_KEY, mine);
        assert_eq!(attempts(&path), 1);
        record_success(&path, &TEST_KEY, later);
        assert_eq!(attempts(&path), 0);
        assert_eq!(
            fs::metadata(rate_limit_path(&path)).unwrap().len(),
            0,
            "a success with nothing outstanding leaves no count or time"
        );
    }

    // A success still holding an epoch that has since been emptied clears
    // nothing counted in the new one.
    #[test]
    fn a_success_from_an_ended_epoch_clears_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        let slow = count_attempt(&path, &TEST_KEY).unwrap();
        let fast = count_attempt(&path, &TEST_KEY).unwrap();
        record_success(&path, &TEST_KEY, fast);
        fail(&path);
        fail(&path);
        record_success(&path, &TEST_KEY, slow);
        assert_eq!(attempts(&path), 2);
    }

    // Two successes running at once, finishing in either order, still leave
    // an attempt counted after both.
    #[test]
    fn overlapping_successes_keep_a_later_attempt() {
        for first_finishes_first in [true, false] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test-storage");
            fs::create_dir(&path).unwrap();

            let first = count_attempt(&path, &TEST_KEY).unwrap();
            let second = count_attempt(&path, &TEST_KEY).unwrap();
            fail(&path);
            let order = if first_finishes_first {
                [first, second]
            } else {
                [second, first]
            };
            for attempt in order {
                record_success(&path, &TEST_KEY, attempt);
            }
            assert_eq!(attempts(&path), 1);
        }
    }

    // A success finishing late, after the limit tripped, does not let the
    // same run of failures trip again.
    #[test]
    fn a_late_success_does_not_trip_the_same_failures_twice() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        let slow = count_attempt(&path, &TEST_KEY).unwrap();
        for _ in 0..MAX_ATTEMPTS {
            fail(&path);
        }
        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        assert_eq!(drain_pending_trips(&path, &TEST_KEY).len(), 1);

        record_success(&path, &TEST_KEY, slow);
        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());
    }

    // A success that clears every attempt a trip covered lets the next run of
    // failures trip.
    #[test]
    fn a_success_clearing_a_trips_attempts_lets_the_next_run_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 1..MAX_ATTEMPTS {
            fail(&path);
        }
        let last_covered = count_attempt(&path, &TEST_KEY).unwrap();
        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        assert_eq!(drain_pending_trips(&path, &TEST_KEY).len(), 1);

        record_success(&path, &TEST_KEY, last_covered);
        for _ in 0..MAX_ATTEMPTS {
            expire_delay_for_tests(&path, &TEST_KEY);
            fail(&path);
        }
        assert_eq!(attempts(&path), MAX_ATTEMPTS + 1);
        assert_eq!(drain_pending_trips(&path, &TEST_KEY).len(), 1);

        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());
    }

    // A record from an earlier release keeps its count and its trip.
    #[test]
    fn an_earlier_releases_record_keeps_its_count() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        let mut old = [0u8; OLD_RECORD_SIZE];
        old[0..4].copy_from_slice(&(MAX_ATTEMPTS + 2).to_le_bytes());
        old[4..12].copy_from_slice(&now_secs().to_le_bytes());
        let tag = compute_hmac(&old[0..12], &TEST_KEY);
        old[12..20].copy_from_slice(&tag);
        fs::write(rate_limit_path(&path), old).unwrap();

        assert_eq!(attempts(&path), MAX_ATTEMPTS + 2);
        assert!(matches!(
            count_attempt(&path, &TEST_KEY),
            Err(KeepError::RateLimited(_))
        ));
        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        assert!(
            drain_pending_trips(&path, &TEST_KEY).is_empty(),
            "the earlier release already queued this trip"
        );
    }

    #[test]
    fn test_file_storage_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("volume.keep");
        File::create(&path).unwrap();

        fail(&path);

        let expected = dir.path().join(".volume.keep.ratelimit");
        assert!(expected.exists());
    }

    #[test]
    fn test_dir_storage_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage");
        fs::create_dir(&path).unwrap();

        fail(&path);

        let expected = path.join(".ratelimit");
        assert!(expected.exists());
    }

    #[test]
    fn test_hmac_detects_corruption() {
        let record = RateLimitRecord {
            epoch: [1; 8],
            counted: 10,
            cleared: 0,
            last_attempt: 12345,
            tripped: 0,
        };
        let mut bytes = record.to_bytes(&TEST_KEY);
        bytes[0] ^= 0xFF;
        assert!(RateLimitRecord::from_bytes(&bytes, &TEST_KEY).is_none());
    }

    #[test]
    fn test_wrong_key_rejects_record() {
        let record = RateLimitRecord {
            epoch: [1; 8],
            counted: 10,
            cleared: 0,
            last_attempt: 12345,
            tripped: 0,
        };
        let bytes = record.to_bytes(&TEST_KEY);
        let wrong_key = [0xCD; 32];
        assert!(RateLimitRecord::from_bytes(&bytes, &wrong_key).is_none());
    }

    #[test]
    fn trip_recorded_exactly_once_on_threshold_crossing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..MAX_ATTEMPTS {
            fail(&path);
        }
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());

        // The next attempt finds five that did not succeed and trips, even
        // though none of the five ever reported back.
        expire_delay_for_tests(&path, &TEST_KEY);
        fail(&path);
        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert_eq!(trips.len(), 1);
        assert_eq!(trips[0].failed_attempts, MAX_ATTEMPTS);
        assert_eq!(trips[0].timestamp, 0, "dated at the fifth attempt");

        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());
    }

    #[test]
    fn additional_failures_past_threshold_do_not_requeue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        trip(&path);
        for _ in 0..3 {
            expire_delay_for_tests(&path, &TEST_KEY);
            fail(&path);
        }

        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert_eq!(trips.len(), 1);
    }

    #[test]
    fn success_does_not_clear_trip_file() {
        // record_success clears the rate-limit counter so the user can keep
        // trying, but the trip event must survive to be flushed by the
        // next unlock that opens an audit log.
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        trip(&path);
        reset_for_tests(&path, &TEST_KEY);

        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert_eq!(trips.len(), 1);
    }

    #[test]
    fn drain_skips_tampered_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        trip(&path);

        let trip_path = trip_log_path(&path);
        let mut bytes = fs::read(&trip_path).unwrap();
        // Flip a bit in the failed_attempts field; HMAC over the data will
        // no longer match, so drain must reject this record.
        bytes[0] ^= 0xFF;
        fs::write(&trip_path, &bytes).unwrap();

        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert!(trips.is_empty(), "tampered record must be silently skipped");
    }

    #[test]
    fn trip_file_capped_at_max_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..=MAX_TRIP_RECORDS {
            trip(&path);
            reset_for_tests(&path, &TEST_KEY);
        }

        let trip_path = trip_log_path(&path);
        let size = fs::metadata(&trip_path).unwrap().len() as usize;
        assert!(
            size <= TRIP_RECORD_SIZE * MAX_TRIP_RECORDS,
            "trip file size {size} exceeded cap"
        );
    }
}
