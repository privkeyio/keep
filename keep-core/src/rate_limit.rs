#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U4;
use blake2::digest::{KeyInit, Mac};
use blake2::Blake2bMac;
use fs2::FileExt;
use subtle::ConstantTimeEq;

const MAX_ATTEMPTS: u32 = 5;
const BASE_DELAY_SECS: u64 = 1;
const MAX_DELAY_SECS: u64 = 300;
const RECORD_SIZE: usize = 16;

fn rate_limit_path(storage_path: &Path) -> PathBuf {
    if storage_path.is_dir() {
        storage_path.join(".ratelimit")
    } else {
        let parent = storage_path.parent().unwrap_or(Path::new("."));
        let name = storage_path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        parent.join(format!(".{}.ratelimit", name))
    }
}

pub(crate) fn derive_hmac_key(salt: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    hasher.update(b"keep-rate-limit-hmac-key");
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

type Blake2bMac32 = Blake2bMac<U4>;

fn compute_hmac(data: &[u8], key: &[u8; 32]) -> [u8; 4] {
    let mut mac = <Blake2bMac32 as KeyInit>::new_from_slice(key).expect("valid key length");
    mac.update(data);
    let result = mac.finalize();
    let mut tag = [0u8; 4];
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
        data[12..16].copy_from_slice(&tag);
        data
    }

    fn from_bytes(data: &[u8], hmac_key: &[u8; 32]) -> Option<Self> {
        if data.len() != RECORD_SIZE {
            return None;
        }
        let tag = compute_hmac(&data[0..12], hmac_key);
        if !bool::from(data[12..16].ct_eq(&tag)) {
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

pub(crate) fn record_failure(path: &Path, hmac_key: &[u8; 32]) {
    let rl_path = rate_limit_path(path);

    let Ok(mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&rl_path)
    else {
        return;
    };

    if FileExt::lock_exclusive(&file).is_err() {
        return;
    }

    let mut record = read_record_from_file(&mut file, hmac_key);
    record.failed_attempts = record.failed_attempts.saturating_add(1);
    record.last_failure = now_secs();

    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.write_all(&record.to_bytes(hmac_key));
    let _ = file.sync_all();
}

pub(crate) fn record_success(path: &Path) {
    let rl_path = rate_limit_path(path);
    let _ = fs::remove_file(rl_path);
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
}
