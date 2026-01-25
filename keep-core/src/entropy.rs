//! Multi-source entropy mixing for defense-in-depth randomness.

use blake2::{Blake2b512, Digest};
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const POOL_SIZE: usize = 128;

static PROCESS_CONTEXT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn hash_to_32(hasher: Blake2b512) -> [u8; 32] {
    let mut output = [0u8; 32];
    output.copy_from_slice(&hasher.finalize()[..32]);
    output
}

fn gather_os_entropy(pool: &mut [u8]) {
    rand::rng().fill_bytes(pool);
}

#[cfg(target_arch = "x86_64")]
fn is_rdrand_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        // SAFETY: __cpuid with leaf 1 is safe on all x86_64 processors.
        // This instruction queries CPU feature flags and does not modify state.
        let result = unsafe { core::arch::x86_64::__cpuid(1) };
        (result.ecx & (1 << 30)) != 0
    })
}

#[cfg(target_arch = "x86_64")]
fn is_rdrand_validated() -> bool {
    static VALIDATED: OnceLock<bool> = OnceLock::new();
    *VALIDATED.get_or_init(|| {
        if !is_rdrand_available() {
            return false;
        }
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        if !fill_rdrand(&mut buf1) || !fill_rdrand(&mut buf2) {
            return false;
        }
        buf1 != buf2
    })
}

#[cfg(target_arch = "x86_64")]
fn rdrand64_with_retry() -> Option<u64> {
    const MAX_RETRIES: u32 = 10;
    let mut val: u64 = 0;
    for _ in 0..MAX_RETRIES {
        // SAFETY: _rdrand64_step is safe to call when RDRAND is available (checked by caller).
        // It writes a random value to `val` and returns 1 on success, 0 on underflow.
        // The instruction does not have side effects beyond writing to the output parameter.
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut val) } == 1 {
            return Some(val);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn fill_rdrand(pool: &mut [u8; 16]) -> bool {
    for chunk in pool.chunks_exact_mut(8) {
        let Some(val) = rdrand64_with_retry() else {
            return false;
        };
        chunk.copy_from_slice(&val.to_le_bytes());
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn gather_rdrand(pool: &mut [u8; 16]) -> bool {
    is_rdrand_validated() && fill_rdrand(pool)
}

#[cfg(not(target_arch = "x86_64"))]
fn gather_rdrand(_pool: &mut [u8; 16]) -> bool {
    false
}

fn gather_timing_jitter() -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    let mut work_buffer = [0u8; 64];

    for i in 0..64 {
        let t1 = std::time::Instant::now();

        for (j, byte) in work_buffer.iter_mut().enumerate() {
            *byte = byte.wrapping_add((i ^ j) as u8);
        }
        std::hint::spin_loop();
        std::sync::atomic::compiler_fence(Ordering::SeqCst);

        let jitter = t1.elapsed().as_nanos() as u64;
        hasher.update(jitter.to_le_bytes());

        let sys_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        hasher.update(sys_time.to_le_bytes());
    }

    hasher.update(work_buffer);
    hash_to_32(hasher)
}

fn gather_process_context() -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());

    let counter = PROCESS_CONTEXT_COUNTER.fetch_add(1, Ordering::Relaxed);
    hasher.update(counter.to_le_bytes());

    let stack_var: u8 = 0;
    hasher.update((&stack_var as *const u8 as usize).to_le_bytes());

    let heap_box = Box::new(0u8);
    hasher.update((&*heap_box as *const u8 as usize).to_le_bytes());

    hash_to_32(hasher)
}

fn mix_entropy(sources: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"keep-entropy-v1");

    for (i, source) in sources.iter().enumerate() {
        hasher.update([i as u8]);
        hasher.update((source.len() as u64).to_le_bytes());
        hasher.update(*source);
    }

    hash_to_32(hasher)
}

fn ensure_entropy_health() -> Result<(), EntropyHealthError> {
    static HEALTH_RESULT: OnceLock<Result<(), EntropyHealthError>> = OnceLock::new();
    *HEALTH_RESULT.get_or_init(check_entropy_health_internal)
}

/// Generates 32 bytes of mixed entropy from multiple sources.
///
/// Sources:
/// - OS randomness (getrandom/urandom via rand crate)
/// - CPU randomness (RDRAND on x86_64 if available)
/// - Timing jitter (high-resolution timestamps with spin loops)
/// - Process context (PID, thread ID, memory addresses)
///
/// All sources are mixed through BLAKE2b-512, truncated to 32 bytes.
///
/// Returns an error if the RNG health check fails.
pub fn random_bytes_mixed() -> Result<[u8; 32], EntropyHealthError> {
    ensure_entropy_health()?;
    Ok(random_bytes_mixed_internal())
}

fn random_bytes_mixed_internal() -> [u8; 32] {
    let mut os_pool = [0u8; POOL_SIZE];
    gather_os_entropy(&mut os_pool);

    let mut rdrand_pool = [0u8; 16];
    let has_rdrand = gather_rdrand(&mut rdrand_pool);

    let timing = gather_timing_jitter();
    let context = gather_process_context();

    if has_rdrand {
        mix_entropy(&[&os_pool, &timing, &context, &rdrand_pool])
    } else {
        mix_entropy(&[&os_pool, &timing, &context])
    }
}

/// Generates N bytes of mixed entropy.
///
/// For requests <= 32 bytes, returns a truncated output from `random_bytes_mixed()`.
/// For larger requests, generates multiple 32-byte blocks with unique counters.
///
/// Returns an error if the RNG health check fails.
pub fn try_random_bytes<const N: usize>() -> Result<[u8; N], EntropyHealthError> {
    ensure_entropy_health()?;

    let mut output = [0u8; N];

    if N <= 32 {
        output.copy_from_slice(&random_bytes_mixed_internal()[..N]);
        return Ok(output);
    }

    for (counter, chunk) in output.chunks_mut(32).enumerate() {
        let block = random_bytes_mixed_internal();
        let mut hasher = Blake2b512::new();
        hasher.update(block);
        hasher.update((counter as u64).to_le_bytes());
        chunk.copy_from_slice(&hasher.finalize()[..chunk.len()]);
    }

    Ok(output)
}

/// Generates N bytes of mixed entropy.
///
/// For requests <= 32 bytes, returns a truncated output from `random_bytes_mixed()`.
/// For larger requests, generates multiple 32-byte blocks with unique counters.
///
/// # Panics
/// Panics if the RNG health check fails (use `try_random_bytes` to handle errors).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    try_random_bytes().expect("RNG health check failed: constant or zero output detected")
}

/// Error returned when RNG health check fails.
#[derive(Debug, Clone, Copy)]
pub struct EntropyHealthError;

impl std::fmt::Display for EntropyHealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RNG health check failed: constant or zero output detected"
        )
    }
}

impl std::error::Error for EntropyHealthError {}

fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn check_bit_distribution(samples: &[[u8; 32]]) -> bool {
    (0..32).all(|pos| {
        let all_zeros = samples.iter().all(|s| s[pos] == 0x00);
        let all_ones = samples.iter().all(|s| s[pos] == 0xff);
        !all_zeros && !all_ones
    })
}

fn check_entropy_health_internal() -> Result<(), EntropyHealthError> {
    let samples: [[u8; 32]; 3] = std::array::from_fn(|_| random_bytes_mixed_internal());

    let all_nonzero = samples.iter().all(|s| s.iter().any(|&b| b != 0));
    let all_unique =
        samples[0] != samples[1] && samples[1] != samples[2] && samples[0] != samples[2];

    if !all_nonzero || !all_unique || !check_bit_distribution(&samples) {
        return Err(EntropyHealthError);
    }

    const MIN_HAMMING: u32 = 64;
    let sufficient_distance = [(0, 1), (1, 2), (0, 2)]
        .iter()
        .all(|&(i, j)| hamming_distance(&samples[i], &samples[j]) >= MIN_HAMMING);

    if !sufficient_distance {
        return Err(EntropyHealthError);
    }

    Ok(())
}

/// Verifies the RNG produces non-constant, non-zero output.
///
/// Generates multiple samples and checks:
/// - Output is not all zeros
/// - Different calls produce different output
/// - Byte positions are not all 0x00 or 0xff across samples
/// - Hamming distance between samples is at least 64 bits
pub fn check_entropy_health() -> Result<(), EntropyHealthError> {
    check_entropy_health_internal()
}

/// Returns whether RDRAND is available on this system.
pub fn has_rdrand() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_rdrand_available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_mixed_produces_output() {
        let bytes = random_bytes_mixed().unwrap();
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_bytes_mixed_different_each_call() {
        let b1 = random_bytes_mixed().unwrap();
        let b2 = random_bytes_mixed().unwrap();
        let b3 = random_bytes_mixed().unwrap();
        assert_ne!(b1, b2);
        assert_ne!(b2, b3);
        assert_ne!(b1, b3);
    }

    #[test]
    fn test_entropy_health_check_passes() {
        assert!(check_entropy_health().is_ok());
    }

    #[test]
    fn test_timing_jitter_produces_output() {
        let t1 = gather_timing_jitter();
        let t2 = gather_timing_jitter();
        assert!(!t1.iter().all(|&b| b == 0));
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_process_context_produces_output() {
        let ctx = gather_process_context();
        assert!(!ctx.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mix_entropy_domain_separation() {
        let data = [1u8; 32];
        let m1 = mix_entropy(&[&data]);
        let m2 = mix_entropy(&[&data, &data]);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_random_bytes_large_buffer() {
        let bytes: [u8; 128] = random_bytes();
        assert!(!bytes.iter().all(|&b| b == 0));
        assert_ne!(&bytes[..32], &bytes[32..64]);
    }
}
