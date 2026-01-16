// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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
pub use kms::{EncryptedWallet, EnvelopeEncryption, KmsProvider, MockKmsProvider};
pub use mock::{AppMode, MockEnclaveClient};
pub use protocol::{
    EnclaveRequest, EnclaveResponse, NetworkParam, PolicyConfig, PolicyDecision, PolicyRule,
    SigningRequest,
};
