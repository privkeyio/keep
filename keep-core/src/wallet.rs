// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Health status of a key share from a liveness check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyHealthStatus {
    /// The FROST group public key.
    pub group_pubkey: [u8; 32],
    /// The share index that was checked.
    pub share_index: u16,
    /// Unix timestamp of the last health check.
    pub last_check_timestamp: u64,
    /// Whether the share was responsive.
    pub responsive: bool,
    /// Unix timestamp when this record was first created (None for legacy records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// 24 hours - key not checked in this period is considered stale.
pub const KEY_HEALTH_STALE_THRESHOLD_SECS: u64 = 86400;
/// 7 days - key not checked in this period is critically stale.
pub const KEY_HEALTH_CRITICAL_THRESHOLD_SECS: u64 = 604800;

impl KeyHealthStatus {
    /// Returns true if the last check is older than the stale threshold (24h).
    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.last_check_timestamp) >= KEY_HEALTH_STALE_THRESHOLD_SECS
    }

    /// Returns true if the last check is older than the critical threshold (7d).
    pub fn is_critical(&self, now: u64) -> bool {
        now.saturating_sub(self.last_check_timestamp) >= KEY_HEALTH_CRITICAL_THRESHOLD_SECS
    }
}

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
