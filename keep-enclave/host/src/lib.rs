#![forbid(unsafe_code)]

mod attestation;
mod client;
mod error;
mod protocol;

pub use attestation::{AttestationVerifier, ExpectedPcrs, VerifiedAttestation};
pub use client::EnclaveClient;
pub use error::{EnclaveError, Result};
pub use protocol::{
    EnclaveRequest, EnclaveResponse, PolicyConfig, PolicyDecision, PolicyRule, SigningRequest,
};
