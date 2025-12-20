#![forbid(unsafe_code)]

mod error;
mod policy;
mod rate_limit;
mod signer;
mod vsock_server;

use error::Result;
use tracing::{error, info};

fn main() {
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt::init();

    info!("Starting Keep enclave");

    if let Err(e) = run() {
        error!("Enclave error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut server = vsock_server::VsockServer::new()?;
    info!("Enclave ready, listening for requests");
    server.run()
}
