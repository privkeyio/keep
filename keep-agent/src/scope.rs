// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use keep_bitcoin::bitcoin::address::{Address, NetworkUnchecked};
use keep_bitcoin::{Network, PsbtAnalysis};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// The one network the session's Bitcoin operations use. The single-key
    /// address is the same output on every network, so letting a caller pick the
    /// network per request would let it render a mainnet spend as testnet.
    #[serde(default)]
    pub network: Option<Network>,
}

impl SessionScope {
    pub fn new(operations: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            operations: operations.into_iter().collect(),
            event_kinds: None,
            max_amount_sats: None,
            address_allowlist: None,
            network: None,
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

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// The scope a session may be created with: Bitcoin operations need a network,
    /// signing also needs a spend limit, and every allowlist entry must be an
    /// address on that network (stored in canonical form).
    pub fn validated(mut self) -> Result<Self> {
        let signs = self.allows_operation(&Operation::SignPsbt);
        if (signs || self.allows_operation(&Operation::GetBitcoinAddress)) && self.network.is_none()
        {
            return Err(AgentError::ScopeViolation(
                "Bitcoin operations need the session's network".into(),
            ));
        }
        if signs && self.max_amount_sats.is_none() {
            return Err(AgentError::ScopeViolation(
                "sign_psbt needs max_amount_sats".into(),
            ));
        }
        if let Some(allowlist) = self.address_allowlist.take() {
            let network = self.network.ok_or_else(|| {
                AgentError::ScopeViolation(
                    "An address allowlist needs the session's network".into(),
                )
            })?;
            let canonical = allowlist
                .iter()
                .map(|a| {
                    canonical_address(a, network).ok_or_else(|| {
                        AgentError::ScopeViolation(format!(
                            "Allowlist entry '{a}' is not an address on {network}"
                        ))
                    })
                })
                .collect::<Result<HashSet<_>>>()?;
            self.address_allowlist = Some(canonical);
        }
        Ok(self)
    }

    /// The session's network. A request may name it, but never another one.
    pub fn bitcoin_network(&self, requested: Option<&str>) -> Result<Network> {
        let network = self.network.ok_or_else(|| {
            AgentError::ScopeViolation("This session has no Bitcoin network".into())
        })?;
        if let Some(name) = requested {
            let named =
                keep_bitcoin::parse_network(name).map_err(|e| AgentError::Other(e.to_string()))?;
            if named != network {
                return Err(AgentError::ScopeViolation(format!(
                    "Network {named} does not match the session's {network}"
                )));
            }
        }
        Ok(network)
    }

    /// Whether the session may sign a PSBT with this analysis. What leaves the wallet,
    /// every output but its change plus the fee, counts toward the limit; change only
    /// counts as change when its script is one of the wallet's change outputs. Every
    /// other output must pay an allowlisted address; one with no address cannot.
    pub fn check_psbt(&self, analysis: &PsbtAnalysis) -> Result<()> {
        let limit = self
            .max_amount_sats
            .ok_or_else(|| AgentError::ScopeViolation("sign_psbt needs max_amount_sats".into()))?;
        let requested = analysis.leaving_wallet_sats();
        if requested > limit {
            return Err(AgentError::AmountExceeded { requested, limit });
        }
        if let Some(allowlist) = &self.address_allowlist {
            for output in analysis.outputs.iter().filter(|o| !o.is_change) {
                match &output.address {
                    Some(addr) if allowlist.contains(addr) => {}
                    Some(addr) => return Err(AgentError::AddressNotAllowed(addr.clone())),
                    None => {
                        return Err(AgentError::AddressNotAllowed(format!(
                            "output {} has no recognizable address",
                            output.index
                        )))
                    }
                }
            }
        }
        Ok(())
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
            Some(allowed) => self
                .network
                .and_then(|n| canonical_address(address, n))
                .is_some_and(|a| allowed.contains(&a)),
            None => true,
        }
    }
}

/// `address` as the signer renders it, if it is an address on `network`.
pub(crate) fn canonical_address(address: &str, network: Network) -> Option<String> {
    let parsed: Address<NetworkUnchecked> = address.parse().ok()?;
    Some(parsed.require_network(network).ok()?.to_string())
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

    // BIP-173 examples: the same witness program on mainnet and testnet.
    const MAINNET_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const TESTNET_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn mainnet_signing() -> SessionScope {
        SessionScope::bitcoin_only()
            .with_network(Network::Bitcoin)
            .with_max_amount(10_000)
    }

    #[test]
    fn test_address_allowlist() {
        let scope = mainnet_signing()
            .with_address_allowlist([MAINNET_ADDR.to_uppercase()])
            .validated()
            .unwrap();
        assert!(scope.allows_address(MAINNET_ADDR));
        assert!(scope.allows_address(&MAINNET_ADDR.to_uppercase()));
        assert!(!scope.allows_address(TESTNET_ADDR));
        assert!(!scope.allows_address("bc1qother"));
    }

    #[test]
    fn validation_needs_a_network_a_limit_and_allowlist_entries_on_that_network() {
        assert!(SessionScope::nostr_only().validated().is_ok());
        let refusal = |scope: SessionScope| match scope.validated() {
            Err(AgentError::ScopeViolation(m)) => m,
            other => panic!("expected a scope violation, got {other:?}"),
        };
        assert!(refusal(SessionScope::bitcoin_only()).contains("network"));
        assert!(refusal(SessionScope::new([Operation::GetBitcoinAddress])).contains("network"));
        assert!(
            refusal(SessionScope::bitcoin_only().with_network(Network::Bitcoin))
                .contains("max_amount_sats")
        );
        assert!(
            refusal(mainnet_signing().with_address_allowlist([TESTNET_ADDR.into()]))
                .contains(TESTNET_ADDR)
        );
        assert!(
            refusal(mainnet_signing().with_address_allowlist(["nope".into()])).contains("nope")
        );
        assert!(
            refusal(SessionScope::nostr_only().with_address_allowlist([MAINNET_ADDR.into()]))
                .contains("network")
        );
        assert!(SessionScope::new([Operation::GetBitcoinAddress])
            .with_network(Network::Testnet)
            .validated()
            .is_ok());
    }

    #[test]
    fn a_request_may_only_confirm_the_sessions_network() {
        let scope = SessionScope::bitcoin_only()
            .with_network(Network::Signet)
            .with_max_amount(1);
        assert_eq!(scope.bitcoin_network(None).unwrap(), Network::Signet);
        assert_eq!(
            scope.bitcoin_network(Some("SIGNET")).unwrap(),
            Network::Signet
        );
        for other in ["testnet", "mainnet", "bitcoin", "regtest"] {
            assert!(
                matches!(
                    scope.bitcoin_network(Some(other)),
                    Err(AgentError::ScopeViolation(_))
                ),
                "{other}"
            );
        }
        for bad in ["", "main", " signet", "testnet4"] {
            assert!(scope.bitcoin_network(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(SessionScope::nostr_only().bitcoin_network(None).is_err());
    }

    fn analysis(outputs: &[(u64, Option<&str>, bool)], fee_sats: u64) -> PsbtAnalysis {
        let outputs: Vec<keep_bitcoin::psbt::OutputInfo> = outputs
            .iter()
            .enumerate()
            .map(
                |(index, &(amount_sats, address, is_change))| keep_bitcoin::psbt::OutputInfo {
                    index,
                    address: address.map(str::to_string),
                    amount_sats,
                    is_change,
                },
            )
            .collect();
        let total_output_sats = outputs
            .iter()
            .map(|o| o.amount_sats)
            .fold(0, u64::saturating_add);
        let total_input_sats = total_output_sats.saturating_add(fee_sats);
        PsbtAnalysis {
            num_inputs: 1,
            num_outputs: outputs.len(),
            total_input_sats,
            total_output_sats,
            fee_sats,
            input_sats: vec![total_input_sats],
            outputs,
            signable_inputs: vec![0],
        }
    }

    #[test]
    fn the_limit_counts_what_leaves_the_wallet() {
        let spend = Some(MAINNET_ADDR);
        assert!(matches!(
            SessionScope::bitcoin_only()
                .with_network(Network::Bitcoin)
                .check_psbt(&analysis(&[(1, spend, false)], 0)),
            Err(AgentError::ScopeViolation(_))
        ));
        let scope = mainnet_signing();
        assert!(scope
            .check_psbt(&analysis(
                &[(8_000, spend, false), (50_000, None, true)],
                2_000
            ))
            .is_ok());
        assert!(matches!(
            scope.check_psbt(&analysis(
                &[(8_001, spend, false), (50_000, None, true)],
                2_000
            )),
            Err(AgentError::AmountExceeded {
                requested: 10_001,
                limit: 10_000
            })
        ));
        assert!(matches!(
            scope.check_psbt(&analysis(
                &[(1_000, spend, false), (1_000, spend, false)],
                8_001
            )),
            Err(AgentError::AmountExceeded {
                requested: 10_001,
                ..
            })
        ));
        assert!(matches!(
            scope.check_psbt(&analysis(&[(u64::MAX, spend, false)], u64::MAX)),
            Err(AgentError::AmountExceeded {
                requested: u64::MAX,
                ..
            })
        ));
    }

    #[test]
    fn the_allowlist_applies_to_every_output_but_change_and_fails_closed() {
        let scope = mainnet_signing()
            .with_address_allowlist([MAINNET_ADDR.into()])
            .validated()
            .unwrap();
        assert!(scope
            .check_psbt(&analysis(
                &[(1_000, Some(MAINNET_ADDR), false), (5_000, None, true)],
                100
            ))
            .is_ok());
        let other = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        assert!(matches!(
            scope.check_psbt(&analysis(&[(1_000, Some(other), false)], 100)),
            Err(AgentError::AddressNotAllowed(a)) if a == other
        ));
        assert!(matches!(
            scope.check_psbt(&analysis(&[(1_000, None, false)], 100)),
            Err(AgentError::AddressNotAllowed(_))
        ));
    }
}
