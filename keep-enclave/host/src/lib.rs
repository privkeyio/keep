// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod attestation;
mod backend;
mod client;
mod error;
mod kms;
mod mock;
mod protocol;

pub use attestation::{AttestationVerifier, ExpectedPcrs, VerifiedAttestation};
pub use backend::SignerBackend;
pub use client::EnclaveClient;
pub use error::{EnclaveError, Result};
pub use kms::{
    policy_update_message, sealed_policy_hash, EncryptedWallet, EnvelopeEncryption, KmsProvider,
    MockKmsProvider, Warden,
};
pub use mock::{AppMode, MockEnclaveClient};
pub use protocol::{
    EnclaveRequest, EnclaveResponse, NetworkParam, PolicyConfig, PolicyDecision, PolicyRule,
    SigningRequest,
};
