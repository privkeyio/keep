// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Entropy source abstraction with AWS Nitro Enclave support.
//!
//! This module provides cryptographically secure random number generation that
//! automatically uses the Nitro Secure Module (NSM) hardware when running inside
//! an AWS Nitro Enclave, falling back to the OS entropy source otherwise.
use rand::Rng;

#[cfg(all(target_os = "linux", feature = "enclave"))]
use aws_nitro_enclaves_nsm_api::driver::nsm_init;

#[cfg(all(target_os = "linux", feature = "enclave"))]
static NSM_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Returns whether the code is running inside an AWS Nitro Enclave.
///
/// This function probes for the NSM device on first call and caches the result.
/// On non-Linux platforms or when the `enclave` feature is disabled, always returns `false`.
///
/// The probe result is also the *only* signal that the NSM is gone, and it is
/// cached for the process lifetime, so a failed probe is reported once here.
/// Without that, the likelier NSM fault -- the device node missing, or the open
/// failing under fd pressure -- makes this return `false`, skips the enclave
/// branch in [`get_entropy`] entirely, and leaves the OS RNG in use with nothing
/// logged. Detecting "are we in an enclave" by probing the very device whose
/// loss we want to hear about cannot distinguish the two on its own; building
/// with the `enclave` feature is the statement that the NSM is expected.
#[cfg(all(target_os = "linux", feature = "enclave"))]
pub fn is_nitro_enclave() -> bool {
    *NSM_AVAILABLE.get_or_init(|| {
        let fd = nsm_init();
        if fd >= 0 {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(fd);
            true
        } else {
            tracing::warn!(
                fd,
                "NSM device did not open; this build expects a Nitro Secure Module, so entropy \
                 will come from the OS RNG for the rest of this process"
            );
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
///
/// Outside an enclave that fallback is the normal path. *Inside* one it is a
/// hardware fault: the NSM is the attested entropy source, and losing it while
/// still producing bytes is exactly the kind of quiet downgrade that stays
/// invisible until someone audits the output. The OS RNG in an enclave is itself
/// NSM-seeded, so substituting it is not weak, but it is never silent either.
pub fn get_entropy<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];

    #[cfg(all(target_os = "linux", feature = "enclave"))]
    if is_nitro_enclave() {
        if fill_from_nsm(&mut buf) {
            return buf;
        }
        // Per draw, not once: unlike a missing device (reported once, from the
        // cached probe in is_nitro_enclave), a failing request is transient, and
        // how often it happens is the signal.
        tracing::error!(
            bytes = N,
            "NSM entropy request failed inside a Nitro Enclave; falling back to the OS RNG"
        );
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
