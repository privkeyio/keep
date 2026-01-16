// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    SignNostrEvent,
    SignPsbt,
    GetPublicKey,
    GetBitcoinAddress,
    Nip44Encrypt,
    Nip44Decrypt,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::SignNostrEvent => "sign_nostr_event",
            Operation::SignPsbt => "sign_psbt",
            Operation::GetPublicKey => "get_public_key",
            Operation::GetBitcoinAddress => "get_bitcoin_address",
            Operation::Nip44Encrypt => "nip44_encrypt",
            Operation::Nip44Decrypt => "nip44_decrypt",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScope {
    pub operations: HashSet<Operation>,
    pub event_kinds: Option<HashSet<u16>>,
    pub max_amount_sats: Option<u64>,
    pub address_allowlist: Option<HashSet<String>>,
}

impl SessionScope {
    pub fn new(operations: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            operations: operations.into_iter().collect(),
            event_kinds: None,
            max_amount_sats: None,
            address_allowlist: None,
        }
    }

    pub fn nostr_only() -> Self {
        Self::new([Operation::SignNostrEvent, Operation::GetPublicKey])
    }

    pub fn bitcoin_only() -> Self {
        Self::new([
            Operation::SignPsbt,
            Operation::GetPublicKey,
            Operation::GetBitcoinAddress,
        ])
    }

    pub fn full() -> Self {
        Self::new([
            Operation::SignNostrEvent,
            Operation::SignPsbt,
            Operation::GetPublicKey,
            Operation::GetBitcoinAddress,
            Operation::Nip44Encrypt,
            Operation::Nip44Decrypt,
        ])
    }

    pub fn with_event_kinds(mut self, kinds: impl IntoIterator<Item = u16>) -> Self {
        self.event_kinds = Some(kinds.into_iter().collect());
        self
    }

    pub fn with_max_amount(mut self, sats: u64) -> Self {
        self.max_amount_sats = Some(sats);
        self
    }

    pub fn with_address_allowlist(mut self, addresses: impl IntoIterator<Item = String>) -> Self {
        self.address_allowlist = Some(addresses.into_iter().collect());
        self
    }

    pub fn allows_operation(&self, op: &Operation) -> bool {
        self.operations.contains(op)
    }

    pub fn allows_event_kind(&self, kind: u16) -> bool {
        match &self.event_kinds {
            Some(allowed) => allowed.contains(&kind),
            None => true,
        }
    }

    pub fn allows_amount(&self, sats: u64) -> bool {
        match self.max_amount_sats {
            Some(max) => sats <= max,
            None => true,
        }
    }

    pub fn allows_address(&self, address: &str) -> bool {
        match &self.address_allowlist {
            Some(allowed) => allowed.contains(address),
            None => true,
        }
    }
}

impl Default for SessionScope {
    fn default() -> Self {
        Self::nostr_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nostr_only_scope() {
        let scope = SessionScope::nostr_only();
        assert!(scope.allows_operation(&Operation::SignNostrEvent));
        assert!(scope.allows_operation(&Operation::GetPublicKey));
        assert!(!scope.allows_operation(&Operation::SignPsbt));
    }

    #[test]
    fn test_event_kind_restrictions() {
        let scope = SessionScope::nostr_only().with_event_kinds([1, 4, 7]);
        assert!(scope.allows_event_kind(1));
        assert!(scope.allows_event_kind(7));
        assert!(!scope.allows_event_kind(30023));
    }

    #[test]
    fn test_amount_limits() {
        let scope = SessionScope::bitcoin_only().with_max_amount(100_000);
        assert!(scope.allows_amount(50_000));
        assert!(scope.allows_amount(100_000));
        assert!(!scope.allows_amount(100_001));
    }

    #[test]
    fn test_address_allowlist() {
        let scope = SessionScope::bitcoin_only()
            .with_address_allowlist(["bc1qtest".to_string(), "bc1ptest".to_string()]);
        assert!(scope.allows_address("bc1qtest"));
        assert!(!scope.allows_address("bc1qother"));
    }
}
