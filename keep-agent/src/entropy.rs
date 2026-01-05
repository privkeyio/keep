//! Entropy source abstraction with AWS Nitro Enclave support.
//!
//! This module provides cryptographically secure random number generation that
//! automatically uses the Nitro Secure Module (NSM) hardware when running inside
//! an AWS Nitro Enclave, falling back to the OS entropy source otherwise.

#![forbid(unsafe_code)]

use rand::RngCore;

#[cfg(all(target_os = "linux", feature = "enclave"))]
use aws_nitro_enclaves_nsm_api::driver::nsm_init;

#[cfg(all(target_os = "linux", feature = "enclave"))]
static NSM_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Returns whether the code is running inside an AWS Nitro Enclave.
///
/// This function probes for the NSM device on first call and caches the result.
/// On non-Linux platforms or when the `enclave` feature is disabled, always returns `false`.
#[cfg(all(target_os = "linux", feature = "enclave"))]
pub fn is_nitro_enclave() -> bool {
    *NSM_AVAILABLE.get_or_init(|| {
        let fd = nsm_init();
        if fd >= 0 {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(fd);
            true
        } else {
            false
        }
    })
}

/// Returns whether the code is running inside an AWS Nitro Enclave.
///
/// This function probes for the NSM device on first call and caches the result.
/// On non-Linux platforms or when the `enclave` feature is disabled, always returns `false`.
#[cfg(not(all(target_os = "linux", feature = "enclave")))]
pub fn is_nitro_enclave() -> bool {
    false
}

/// Returns cryptographically secure random bytes.
///
/// When running inside an AWS Nitro Enclave (with the `enclave` feature enabled),
/// uses the hardware NSM for entropy. Falls back to the OS entropy source otherwise.
pub fn get_entropy<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];

    #[cfg(all(target_os = "linux", feature = "enclave"))]
    if is_nitro_enclave() && fill_from_nsm(&mut buf) {
        return buf;
    }

    rand::rng().fill_bytes(&mut buf);
    buf
}

#[cfg(all(target_os = "linux", feature = "enclave"))]
fn fill_from_nsm(buf: &mut [u8]) -> bool {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        return false;
    }

    let mut filled = 0;
    while filled < buf.len() {
        let request = Request::GetRandom {};
        let response = nsm_process_request(fd, request);

        match response {
            Response::GetRandom { random } => {
                let copy_len = (buf.len() - filled).min(random.len());
                if copy_len == 0 {
                    // Empty response would cause infinite loop
                    nsm_exit(fd);
                    return false;
                }
                buf[filled..filled + copy_len].copy_from_slice(&random[..copy_len]);
                filled += copy_len;
            }
            _ => {
                nsm_exit(fd);
                return false;
            }
        }
    }

    nsm_exit(fd);
    true
}
