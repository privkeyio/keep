// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(unused_assignments)]

use crate::address::AddressDerivation;
use crate::descriptor::DescriptorExport;
use crate::error::{BitcoinError, Result};
use crate::psbt::{PsbtAnalysis, PsbtSigner};
use bitcoin::psbt::Psbt;
use bitcoin::Network;

pub struct BitcoinSigner {
    network: Network,
    address_derivation: AddressDerivation,
    psbt_signer: PsbtSigner,
    policy: Option<SigningPolicy>,
}

#[derive(Clone, Debug, Default)]
pub struct SigningPolicy {
    pub max_amount_sats: Option<u64>,
    pub address_allowlist: Option<Vec<String>>,
    pub address_blocklist: Option<Vec<String>>,
    pub require_change_output: bool,
}

impl BitcoinSigner {
    pub fn new(secret: &mut [u8; 32], network: Network) -> Result<Self> {
        let address_derivation = AddressDerivation::new(secret, network)?;
        let psbt_signer = PsbtSigner::new(secret, network)?;

        Ok(Self {
            network,
            address_derivation,
            psbt_signer,
            policy: None,
        })
    }

    pub fn with_policy(mut self, policy: SigningPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn set_policy(&mut self, policy: SigningPolicy) {
        self.policy = Some(policy);
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn get_receive_address(&self, index: u32) -> Result<String> {
        let derived = self.address_derivation.get_receive_address(index)?;
        Ok(derived.address.to_string())
    }

    pub fn get_change_address(&self, index: u32) -> Result<String> {
        let derived = self.address_derivation.get_change_address(index)?;
        Ok(derived.address.to_string())
    }

    pub fn get_addresses(&self, count: u32) -> Result<Vec<String>> {
        let addresses = self.address_derivation.get_receive_addresses(count)?;
        Ok(addresses
            .into_iter()
            .map(|a| a.address.to_string())
            .collect())
    }

    pub fn export_descriptor(&self, account: u32) -> Result<DescriptorExport> {
        DescriptorExport::from_derivation(&self.address_derivation, account)
    }

    pub fn analyze_psbt(&self, psbt: &Psbt) -> Result<PsbtAnalysis> {
        self.psbt_signer.analyze(psbt)
    }

    pub fn check_policy(&self, analysis: &PsbtAnalysis) -> Result<()> {
        let policy = match &self.policy {
            Some(p) => p,
            None => return Ok(()),
        };

        let spend_amount: u64 = analysis
            .outputs
            .iter()
            .filter(|o| !o.is_change)
            .map(|o| o.amount_sats)
            .sum();

        if let Some(max) = policy.max_amount_sats {
            if spend_amount > max {
                return Err(BitcoinError::AmountExceeded {
                    amount: spend_amount,
                    limit: max,
                });
            }
        }

        if let Some(allowlist) = &policy.address_allowlist {
            for output in &analysis.outputs {
                if output.is_change {
                    continue;
                }
                if let Some(addr) = &output.address {
                    if !allowlist.contains(addr) {
                        return Err(BitcoinError::AddressNotAllowed(addr.clone()));
                    }
                }
            }
        }

        if let Some(blocklist) = &policy.address_blocklist {
            for output in &analysis.outputs {
                if let Some(addr) = &output.address {
                    if blocklist.contains(addr) {
                        return Err(BitcoinError::PolicyDenied(format!(
                            "Address {addr} is blocked"
                        )));
                    }
                }
            }
        }

        if policy.require_change_output {
            let has_change = analysis.outputs.iter().any(|o| o.is_change);
            if !has_change {
                return Err(BitcoinError::PolicyDenied(
                    "Transaction must have change output".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<usize> {
        let analysis = self.analyze_psbt(psbt)?;
        self.check_policy(&analysis)?;
        self.psbt_signer.sign(psbt)
    }

    pub fn sign_psbt_unchecked(&self, psbt: &mut Psbt) -> Result<usize> {
        self.psbt_signer.sign(psbt)
    }

    pub fn x_only_public_key(&self) -> [u8; 32] {
        self.psbt_signer.x_only_public_key().serialize()
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.address_derivation.master_fingerprint()?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_signer() {
        let mut secret = [1u8; 32];
        let signer = BitcoinSigner::new(&mut secret, Network::Testnet).unwrap();

        let addr = signer.get_receive_address(0).unwrap();
        assert!(addr.starts_with("tb1p"));
    }

    #[test]
    fn test_signer_with_policy() {
        let mut secret = [2u8; 32];
        let policy = SigningPolicy {
            max_amount_sats: Some(100_000),
            address_allowlist: None,
            address_blocklist: None,
            require_change_output: false,
        };

        let signer = BitcoinSigner::new(&mut secret, Network::Testnet)
            .unwrap()
            .with_policy(policy);

        assert!(signer.policy.is_some());
    }

    #[test]
    fn test_export_descriptor() {
        let mut secret = [3u8; 32];
        let signer = BitcoinSigner::new(&mut secret, Network::Testnet).unwrap();

        let export = signer.export_descriptor(0).unwrap();
        assert!(export.descriptor.contains("tr("));
    }

    #[test]
    fn test_multiple_addresses() {
        let mut secret = [4u8; 32];
        let signer = BitcoinSigner::new(&mut secret, Network::Testnet).unwrap();

        let addresses = signer.get_addresses(5).unwrap();
        assert_eq!(addresses.len(), 5);

        let unique: std::collections::HashSet<_> = addresses.iter().collect();
        assert_eq!(unique.len(), 5);
    }
}
