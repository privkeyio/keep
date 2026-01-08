// SAFETY: We use `deny(unsafe_code)` instead of `forbid(unsafe_code)` to allow a single,
// reviewed exception in the `mlock` module. That module uses unsafe code for:
// - Memory locking via mlock(2) to prevent secrets from being swapped to disk
// - Secure zeroing of sensitive data via memsec::memzero before deallocation
// The unsafe code is intentionally scoped to MlockedBox and MlockedVec types only.
// Reviewed in commit 731ef80 (mlock memory safety audit). Any new unsafe usage requires review.
#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
mod aws_credentials;
mod audit;
mod error;
mod kms;
#[cfg(target_os = "linux")]
mod kmstool;
mod mlock;
mod policy;
mod rate_limit;
mod signer;
mod vsock_server;

use error::Result;

fn main() {
    #[cfg(feature = "tracing")]
    {
        tracing_subscriber::fmt::init();
        tracing::info!("Starting Keep enclave");
    }

    if let Err(e) = run() {
        #[cfg(feature = "tracing")]
        tracing::error!("Enclave error: {}", e);
        #[cfg(not(feature = "tracing"))]
        eprintln!("Enclave error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut server = vsock_server::VsockServer::new()?;
    #[cfg(feature = "tracing")]
    tracing::info!("Enclave ready, listening for requests");
    server.run()
}
