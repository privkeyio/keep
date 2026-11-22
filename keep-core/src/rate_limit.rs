// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::fs::{self, File, OpenOptions};
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
const RECORD_SIZE: usize = 20;

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

struct RateLimitRecord {
    failed_attempts: u32,
    last_failure: u64,
}

impl RateLimitRecord {
    fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_failure: 0,
        }
    }

    fn to_bytes(&self, hmac_key: &[u8; 32]) -> [u8; RECORD_SIZE] {
        let mut data = [0u8; RECORD_SIZE];
        data[0..4].copy_from_slice(&self.failed_attempts.to_le_bytes());
        data[4..12].copy_from_slice(&self.last_failure.to_le_bytes());
        let tag = compute_hmac(&data[0..12], hmac_key);
        data[12..20].copy_from_slice(&tag);
        data
    }

    fn from_bytes(data: &[u8], hmac_key: &[u8; 32]) -> Option<Self> {
        if data.len() != RECORD_SIZE {
            return None;
        }
        let tag = compute_hmac(&data[0..12], hmac_key);
        if !bool::from(data[12..20].ct_eq(&tag)) {
            return None;
        }
        Some(Self {
            failed_attempts: u32::from_le_bytes(data[0..4].try_into().ok()?),
            last_failure: u64::from_le_bytes(data[4..12].try_into().ok()?),
        })
    }

    fn delay_duration(&self) -> Duration {
        if self.failed_attempts < MAX_ATTEMPTS {
            return Duration::ZERO;
        }
        let excess = self.failed_attempts - MAX_ATTEMPTS;
        let delay_secs = BASE_DELAY_SECS.saturating_mul(1u64 << excess.min(8));
        Duration::from_secs(delay_secs.min(MAX_DELAY_SECS))
    }

    fn remaining_delay(&self) -> Duration {
        if self.last_failure == 0 {
            return Duration::ZERO;
        }
        let elapsed = now_secs().saturating_sub(self.last_failure);
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

/// Count an unlock attempt before its password is tried, or refuse it.
///
/// Refuses while the record says to wait, and when the record cannot be
/// opened, locked, written or synced: an attempt that is not on disk before
/// the password check could go uncounted, through a full disk, a crash during
/// key derivation, or several attempts reading the same count at once. A
/// success then removes the record, so only attempts that did not succeed
/// stay counted.
pub(crate) fn count_attempt(path: &Path, hmac_key: &[u8; 32]) -> Result<(), KeepError> {
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

    let (prior, prior_time) = (record.failed_attempts, record.last_failure);
    record.failed_attempts = record.failed_attempts.saturating_add(1);
    record.last_failure = now_secs();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&record.to_bytes(hmac_key)))
        .and_then(|()| file.sync_all())
        .map_err(unusable)?;

    // A success removes the record, so `prior` attempts all failed or never
    // finished. Queued here, under the lock, the trip is recorded once per
    // cycle and cannot be skipped by abandoning an attempt.
    if prior == MAX_ATTEMPTS {
        record_trip(path, hmac_key, prior, prior_time);
    }
    drop(file);
    Ok(())
}

fn open_rate_limit_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    no_follow(&mut opts);
    opts.open(path)
}

// The record's path is fixed inside the vault folder, and a link planted there
// would have its target overwritten with a record.
fn no_follow(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = opts;
}

pub(crate) fn record_success(path: &Path) {
    let rl_path = rate_limit_path(path);
    let _ = fs::remove_file(rl_path);
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
    no_follow(&mut opts);
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
        failed_attempts,
        last_failure: now_secs(),
    };
    fs::write(rate_limit_path(path), record.to_bytes(hmac_key)).unwrap();
}

/// Let the current back-off run out, keeping the count, as waiting would.
#[cfg(test)]
pub(crate) fn expire_delay_for_tests(path: &Path, hmac_key: &[u8; 32]) {
    let mut file = File::open(rate_limit_path(path)).unwrap();
    let mut record = read_record_from_file(&mut file, hmac_key).unwrap();
    record.last_failure = 0;
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
    no_follow(&mut opts);
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
            record.failed_attempts += 1;
        }
        assert_eq!(record.delay_duration(), Duration::ZERO);

        record.failed_attempts += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(1));

        record.failed_attempts += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(2));

        record.failed_attempts += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(4));

        record.failed_attempts += 1;
        assert_eq!(record.delay_duration(), Duration::from_secs(8));
    }

    #[test]
    fn test_max_delay_cap() {
        let mut record = RateLimitRecord::new();
        record.failed_attempts = 50;
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

        record_success(&path);
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
        read_record_from_file(&mut file, &TEST_KEY)
            .unwrap()
            .failed_attempts
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

        record_success(&path);
        assert!(!rate_limit_path(&path).exists());
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
            read_record_from_file(&mut short, &TEST_KEY)
                .unwrap()
                .failed_attempts,
            0
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
            failed_attempts: 10,
            last_failure: 12345,
        };
        let mut bytes = record.to_bytes(&TEST_KEY);
        bytes[0] ^= 0xFF;
        assert!(RateLimitRecord::from_bytes(&bytes, &TEST_KEY).is_none());
    }

    #[test]
    fn test_wrong_key_rejects_record() {
        let record = RateLimitRecord {
            failed_attempts: 10,
            last_failure: 12345,
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
        record_success(&path);

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
            record_success(&path);
        }

        let trip_path = trip_log_path(&path);
        let size = fs::metadata(&trip_path).unwrap().len() as usize;
        assert!(
            size <= TRIP_RECORD_SIZE * MAX_TRIP_RECORDS,
            "trip file size {size} exceeded cap"
        );
    }
}
