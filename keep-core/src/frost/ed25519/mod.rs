// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! FROST over Ed25519.
//!
//! Parallel to the secp256k1 modules under `crate::frost`, this submodule binds
//! the FROST protocol to the Ed25519 ciphersuite while reusing the
//! ciphersuite-agnostic share, storage, and transport types.
//!
//! Provides trusted-dealer key generation, the share storage round-trip, and
//! offline t-of-n release signing/verification.

mod dealer;
pub mod minisign;
mod signer;

pub use dealer::TrustedDealer;
pub use signer::{sign_with_local_shares, verify};
