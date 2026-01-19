//! Multi-source entropy mixing for defense-in-depth randomness.

use blake2::{Blake2b512, Digest};
use rand::RngCore;

const POOL_SIZE: usize = 128;

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
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let result = unsafe { core::arch::x86_64::__cpuid(1) };
        (result.ecx & (1 << 30)) != 0
    })
}

#[cfg(target_arch = "x86_64")]
fn fill_rdrand(pool: &mut [u8; 16]) -> bool {
    const MAX_RETRIES: u32 = 10;
    for chunk in pool.chunks_exact_mut(8) {
        let mut val: u64 = 0;
        let mut success = false;
        for _ in 0..MAX_RETRIES {
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut val) } == 1 {
                success = true;
                break;
            }
        }
        if !success {
            return false;
        }
        chunk.copy_from_slice(&val.to_le_bytes());
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn gather_rdrand(pool: &mut [u8; 16]) -> bool {
    is_rdrand_available() && fill_rdrand(pool)
}

#[cfg(not(target_arch = "x86_64"))]
fn gather_rdrand(_pool: &mut [u8; 16]) -> bool {
    false
}

fn gather_timing_jitter() -> [u8; 32] {
    let mut hasher = Blake2b512::new();

    for _ in 0..8 {
        let t1 = std::time::Instant::now();
        std::hint::spin_loop();
        let jitter = t1.elapsed().as_nanos() as u64;
        hasher.update(jitter.to_le_bytes());

        let sys_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        hasher.update(sys_time.to_le_bytes());
    }

    hash_to_32(hasher)
}

fn gather_process_context() -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());

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

/// Generates 32 bytes of mixed entropy from multiple sources.
///
/// Sources:
/// - OS randomness (getrandom/urandom via rand crate)
/// - CPU randomness (RDRAND on x86_64 if available)
/// - Timing jitter (high-resolution timestamps with spin loops)
/// - Process context (PID, thread ID, memory addresses)
///
/// All sources are mixed through BLAKE2b-512, truncated to 32 bytes.
pub fn random_bytes_mixed() -> [u8; 32] {
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
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut output = [0u8; N];

    if N <= 32 {
        let mixed = random_bytes_mixed();
        output.copy_from_slice(&mixed[..N]);
    } else {
        let mut offset = 0;
        let mut counter: u64 = 0;
        while offset < N {
            let block = random_bytes_mixed();
            let mut hasher = Blake2b512::new();
            hasher.update(block);
            hasher.update(counter.to_le_bytes());
            let result = hasher.finalize();

            let remaining = N - offset;
            let copy_len = remaining.min(32);
            output[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);
            offset += copy_len;
            counter += 1;
        }
    }

    output
}

/// Error returned when RNG health check fails.
#[derive(Debug)]
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

/// Verifies the RNG produces non-constant, non-zero output.
///
/// Generates multiple samples and checks:
/// - Output is not all zeros
/// - Different calls produce different output
pub fn check_entropy_health() -> Result<(), EntropyHealthError> {
    let samples = [
        random_bytes_mixed(),
        random_bytes_mixed(),
        random_bytes_mixed(),
    ];

    let all_nonzero = samples.iter().all(|s| s.iter().any(|&b| b != 0));
    let all_unique =
        samples[0] != samples[1] && samples[1] != samples[2] && samples[0] != samples[2];

    if all_nonzero && all_unique {
        Ok(())
    } else {
        Err(EntropyHealthError)
    }
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
        let bytes = random_bytes_mixed();
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_bytes_mixed_different_each_call() {
        let b1 = random_bytes_mixed();
        let b2 = random_bytes_mixed();
        let b3 = random_bytes_mixed();
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
