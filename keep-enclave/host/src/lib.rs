#![forbid(unsafe_code)]

mod attestation;
mod client;
mod error;
mod kms;
mod mock;
mod protocol;

pub use attestation::{AttestationVerifier, ExpectedPcrs, VerifiedAttestation};
pub use client::EnclaveClient;
pub use error::{EnclaveError, Result};
pub use kms::{EncryptedWallet, EnvelopeEncryption, KmsProvider, MockKmsProvider};
pub use mock::{AppMode, MockEnclaveClient};
pub use protocol::{
    EnclaveRequest, EnclaveResponse, PolicyConfig, PolicyDecision, PolicyRule, SigningRequest,
};
