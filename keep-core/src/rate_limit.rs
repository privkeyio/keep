// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U8;
use blake2::digest::{KeyInit, Mac};
use blake2::Blake2bMac;
use fs2::FileExt;
use subtle::ConstantTimeEq;

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

fn read_record_from_file(file: &mut File, hmac_key: &[u8; 32]) -> RateLimitRecord {
    let mut data = [0u8; RECORD_SIZE];
    if file.read_exact(&mut data).is_ok() {
        RateLimitRecord::from_bytes(&data, hmac_key).unwrap_or_else(RateLimitRecord::new)
    } else {
        RateLimitRecord::new()
    }
}

pub(crate) fn check_rate_limit(path: &Path, hmac_key: &[u8; 32]) -> Result<(), Duration> {
    let rl_path = rate_limit_path(path);

    let Ok(mut file) = File::open(&rl_path) else {
        return Ok(());
    };

    if FileExt::lock_shared(&file).is_err() {
        return Err(Duration::from_secs(MAX_DELAY_SECS));
    }

    let record = read_record_from_file(&mut file, hmac_key);
    let remaining = record.remaining_delay();

    if remaining > Duration::ZERO {
        Err(remaining)
    } else {
        Ok(())
    }
}

fn open_rate_limit_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

pub(crate) fn record_failure(path: &Path, hmac_key: &[u8; 32]) {
    let rl_path = rate_limit_path(path);

    let Ok(mut file) = open_rate_limit_file(&rl_path) else {
        return;
    };

    if FileExt::lock_exclusive(&file).is_err() {
        return;
    }

    let mut record = read_record_from_file(&mut file, hmac_key);
    let prior_attempts = record.failed_attempts;
    record.failed_attempts = record.failed_attempts.saturating_add(1);
    record.last_failure = now_secs();

    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.write_all(&record.to_bytes(hmac_key));
    let _ = file.sync_all();

    // Queue a trip event the first time this failure crosses the rate-limit
    // threshold. Successive failures while already tripped do not enqueue
    // additional events. The trip log persists across the failed-attempt
    // cycle and is drained by the next successful unlock when the audit log
    // is available (the data key required to write encrypted audit entries
    // is not available at this point in the flow, see #495).
    if prior_attempts < MAX_ATTEMPTS && record.failed_attempts >= MAX_ATTEMPTS {
        record_trip(path, hmac_key, record.failed_attempts, record.last_failure);
    }
}

pub(crate) fn record_success(path: &Path) {
    let rl_path = rate_limit_path(path);
    let _ = fs::remove_file(rl_path);
}

/// A persisted rate-limit trip event awaiting flush to the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingTrip {
    pub failed_attempts: u32,
    pub timestamp: u64,
}

const TRIP_RECORD_SIZE: usize = 20;
const MAX_TRIP_RECORDS: usize = 256;

impl PendingTrip {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let Ok(file) = opts.open(&trip_path) else {
        return;
    };

    if FileExt::lock_exclusive(&file).is_err() {
        return;
    }

    // Cap the file at MAX_TRIP_RECORDS to bound disk usage when nothing
    // flushes (e.g. hidden-volume unlock paths that don't open an audit log).
    if let Ok(meta) = file.metadata() {
        if meta.len() as usize >= TRIP_RECORD_SIZE * MAX_TRIP_RECORDS {
            return;
        }
    }

    let trip = PendingTrip {
        failed_attempts,
        timestamp,
    };
    let mut file = file;
    let _ = file.write_all(&trip.to_bytes(hmac_key));
    let _ = file.sync_all();
}

/// Read and remove all pending trip events for `path`. Records with invalid
/// HMAC tags are silently skipped (cannot be attributed to a real trip).
pub(crate) fn drain_pending_trips(path: &Path, hmac_key: &[u8; 32]) -> Vec<PendingTrip> {
    let trip_path = trip_log_path(path);

    let Ok(mut file) = File::open(&trip_path) else {
        return Vec::new();
    };

    if FileExt::lock_exclusive(&file).is_err() {
        return Vec::new();
    }

    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(buf.len() / TRIP_RECORD_SIZE);
    for chunk in buf.chunks_exact(TRIP_RECORD_SIZE) {
        if let Some(trip) = PendingTrip::from_bytes(chunk, hmac_key) {
            out.push(trip);
        }
    }

    drop(file);
    let _ = fs::remove_file(&trip_path);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    #[test]
    fn test_no_delay_on_first_attempts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..MAX_ATTEMPTS {
            assert!(check_rate_limit(&path, &TEST_KEY).is_ok());
            record_failure(&path, &TEST_KEY);
        }
    }

    #[test]
    fn test_delay_after_max_attempts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..=MAX_ATTEMPTS {
            let _ = check_rate_limit(&path, &TEST_KEY);
            record_failure(&path, &TEST_KEY);
        }

        let result = check_rate_limit(&path, &TEST_KEY);
        assert!(result.is_err());
        assert!(result.unwrap_err().as_secs() >= BASE_DELAY_SECS);
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
            let _ = check_rate_limit(&path, &TEST_KEY);
            record_failure(&path, &TEST_KEY);
        }

        record_success(&path);
        assert!(check_rate_limit(&path, &TEST_KEY).is_ok());
    }

    #[test]
    fn test_persists_across_reads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..=MAX_ATTEMPTS {
            record_failure(&path, &TEST_KEY);
        }

        assert!(check_rate_limit(&path, &TEST_KEY).is_err());

        drop(dir);
    }

    #[test]
    fn test_file_storage_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("volume.keep");
        File::create(&path).unwrap();

        record_failure(&path, &TEST_KEY);

        let expected = dir.path().join(".volume.keep.ratelimit");
        assert!(expected.exists());
    }

    #[test]
    fn test_dir_storage_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage");
        fs::create_dir(&path).unwrap();

        record_failure(&path, &TEST_KEY);

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

        // Drive the counter up to MAX_ATTEMPTS - 1 with no trip recorded.
        for _ in 0..(MAX_ATTEMPTS - 1) {
            record_failure(&path, &TEST_KEY);
        }
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());

        // This failure crosses the threshold and must queue exactly one trip.
        record_failure(&path, &TEST_KEY);
        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert_eq!(trips.len(), 1);
        assert_eq!(trips[0].failed_attempts, MAX_ATTEMPTS);

        // After draining, the trip file is gone.
        assert!(drain_pending_trips(&path, &TEST_KEY).is_empty());
    }

    #[test]
    fn additional_failures_past_threshold_do_not_requeue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..=MAX_ATTEMPTS {
            record_failure(&path, &TEST_KEY);
        }

        // We expect exactly one trip (the first to cross), regardless of how
        // many failures piled on after.
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

        for _ in 0..=MAX_ATTEMPTS {
            record_failure(&path, &TEST_KEY);
        }
        record_success(&path);

        let trips = drain_pending_trips(&path, &TEST_KEY);
        assert_eq!(trips.len(), 1);
    }

    #[test]
    fn drain_skips_tampered_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-storage");
        fs::create_dir(&path).unwrap();

        for _ in 0..=MAX_ATTEMPTS {
            record_failure(&path, &TEST_KEY);
        }

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

        // Synthesize MAX_TRIP_RECORDS valid records by repeatedly tripping
        // and resetting the counter so each call crosses the threshold.
        for _ in 0..MAX_TRIP_RECORDS {
            // Drive up to MAX_ATTEMPTS then reset.
            for _ in 0..MAX_ATTEMPTS {
                record_failure(&path, &TEST_KEY);
            }
            record_success(&path);
        }
        // One more cycle must not push the file past the cap.
        for _ in 0..MAX_ATTEMPTS {
            record_failure(&path, &TEST_KEY);
        }

        let trip_path = trip_log_path(&path);
        let size = fs::metadata(&trip_path).unwrap().len() as usize;
        assert!(
            size <= TRIP_RECORD_SIZE * MAX_TRIP_RECORDS,
            "trip file size {size} exceeded cap"
        );
    }
}
