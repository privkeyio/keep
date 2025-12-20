#![forbid(unsafe_code)]

mod error;
mod kms;
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
