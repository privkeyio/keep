// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid PSBT: {0}")]
    InvalidPsbt(String),

    #[error("Missing witness UTXO for input {0}")]
    MissingWitnessUtxo(usize),

    #[error("Sighash computation failed: {0}")]
    Sighash(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Derivation path error: {0}")]
    DerivationPath(String),

    #[error("Address generation failed: {0}")]
    Address(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Amount {amount} sats exceeds limit {limit} sats")]
    AmountExceeded { amount: u64, limit: u64 },

    #[error("Address {0} not in allowlist")]
    AddressNotAllowed(String),

    #[error("Descriptor error: {0}")]
    Descriptor(String),

    #[error("Recovery error: {0}")]
    Recovery(String),
}

pub type Result<T> = std::result::Result<T, BitcoinError>;
