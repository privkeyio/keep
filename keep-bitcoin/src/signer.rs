// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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

        let spend_amount = analysis.leaving_wallet_sats();

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
                // Fail closed: an output with no recognizable address cannot be
                // checked against the allowlist.
                match &output.address {
                    Some(addr) if allowlist.contains(addr) => {}
                    Some(addr) => return Err(BitcoinError::AddressNotAllowed(addr.clone())),
                    None => {
                        return Err(BitcoinError::AddressNotAllowed(format!(
                            "output {} has no recognizable address",
                            output.index
                        )))
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

    fn analysis(outputs: &[(u64, Option<&str>, bool)], fee_sats: u64) -> PsbtAnalysis {
        let outputs: Vec<crate::psbt::OutputInfo> = outputs
            .iter()
            .enumerate()
            .map(
                |(index, (amount_sats, address, is_change))| crate::psbt::OutputInfo {
                    index,
                    address: address.map(str::to_string),
                    amount_sats: *amount_sats,
                    is_change: *is_change,
                },
            )
            .collect();
        let total_output_sats = outputs.iter().map(|o| o.amount_sats).sum::<u64>();
        PsbtAnalysis {
            num_inputs: 1,
            num_outputs: outputs.len(),
            total_input_sats: total_output_sats + fee_sats,
            total_output_sats,
            fee_sats,
            input_sats: vec![total_output_sats + fee_sats],
            outputs,
            signable_inputs: vec![0],
        }
    }

    fn signer_with(policy: SigningPolicy) -> BitcoinSigner {
        let mut secret = [5u8; 32];
        BitcoinSigner::new(&mut secret, Network::Testnet)
            .unwrap()
            .with_policy(policy)
    }

    #[test]
    fn the_amount_limit_counts_the_fee() {
        let signer = signer_with(SigningPolicy {
            max_amount_sats: Some(10_000),
            ..Default::default()
        });
        assert!(signer
            .check_policy(&analysis(&[(5_000, Some("a"), false)], 4_000))
            .is_ok());
        assert!(matches!(
            signer.check_policy(&analysis(
                &[(5_000, Some("a"), false), (90_000, Some("c"), true)],
                55_000
            )),
            Err(BitcoinError::AmountExceeded {
                amount: 60_000,
                limit: 10_000
            })
        ));
    }

    #[test]
    fn the_allowlist_refuses_outputs_without_an_address() {
        let signer = signer_with(SigningPolicy {
            address_allowlist: Some(vec!["a".into()]),
            ..Default::default()
        });
        assert!(signer
            .check_policy(&analysis(&[(5_000, Some("a"), false)], 100))
            .is_ok());
        assert!(matches!(
            signer.check_policy(&analysis(&[(5_000, Some("b"), false)], 100)),
            Err(BitcoinError::AddressNotAllowed(_))
        ));
        assert!(matches!(
            signer.check_policy(&analysis(&[(5_000, None, false)], 100)),
            Err(BitcoinError::AddressNotAllowed(_))
        ));
        assert!(signer
            .check_policy(&analysis(
                &[(5_000, Some("a"), false), (1_000, None, true)],
                100
            ))
            .is_ok());
    }
}
