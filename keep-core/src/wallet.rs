// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A finalized wallet descriptor associated with a FROST group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletDescriptor {
    /// The FROST group public key this descriptor belongs to.
    pub group_pubkey: [u8; 32],
    /// The external (receive) descriptor string.
    pub external_descriptor: String,
    /// The internal (change) descriptor string.
    pub internal_descriptor: String,
    /// The Bitcoin network (e.g. "bitcoin", "testnet", "signet", "regtest").
    pub network: String,
    /// Unix timestamp when the descriptor was created.
    pub created_at: u64,
}
