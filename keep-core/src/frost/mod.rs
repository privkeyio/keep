// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! FROST threshold signature implementation.
//!
//! This module provides threshold signatures using the FROST protocol,
//! allowing multiple parties to collaboratively sign messages without
//! any single party having access to the complete private key.
mod coordinator;
mod dealer;
mod refresh;
mod share;
mod signing;
mod transport;

pub use coordinator::Coordinator;
pub use dealer::{ThresholdConfig, TrustedDealer};
pub use refresh::refresh_shares;
pub use share::{ShareMetadata, SharePackage, StoredShare};
pub use signing::{sign_with_local_shares, SessionState, SigningSession};
pub use transport::{FrostMessage, FrostMessageType, ShareExport};
