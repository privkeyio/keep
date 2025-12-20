#![forbid(unsafe_code)]

use crate::error::{BitcoinError, Result};
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::{Address, Network, XOnlyPublicKey};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct DerivedAddress {
    pub address: Address,
    pub path: DerivationPath,
    pub public_key: XOnlyPublicKey,
    pub index: u32,
}

pub struct AddressDerivation {
    master_xpriv: Xpriv,
    secp: Secp256k1<All>,
    network: Network,
}

impl AddressDerivation {
    pub fn new(secret: &[u8; 32], network: Network) -> Result<Self> {
        let secp = Secp256k1::new();

        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(secret)
            .map_err(|e| BitcoinError::InvalidSecretKey(e.to_string()))?;

        let master_xpriv = Xpriv::new_master(network, secret).map_err(|e| {
            BitcoinError::DerivationPath(format!("Failed to create master key: {}", e))
        })?;

        let _ = secret_key;

        Ok(Self {
            master_xpriv,
            secp,
            network,
        })
    }

    pub fn derive_taproot_address(
        &self,
        account: u32,
        change: bool,
        index: u32,
    ) -> Result<DerivedAddress> {
        let coin_type = if self.network == Network::Bitcoin {
            0
        } else {
            1
        };

        let path_str = format!(
            "m/86'/{}'/{}'/{}/{}",
            coin_type,
            account,
            if change { 1 } else { 0 },
            index,
        );

        let path = DerivationPath::from_str(&path_str)
            .map_err(|e| BitcoinError::DerivationPath(format!("Invalid path: {}", e)))?;

        let child_xpriv = self
            .master_xpriv
            .derive_priv(&self.secp, &path)
            .map_err(|e| BitcoinError::DerivationPath(format!("Derivation failed: {}", e)))?;

        let child_keypair = child_xpriv.to_keypair(&self.secp);
        let (x_only_pk, _parity) = child_keypair.x_only_public_key();

        let address = Address::p2tr(&self.secp, x_only_pk, None, self.network);

        Ok(DerivedAddress {
            address,
            path,
            public_key: x_only_pk,
            index,
        })
    }

    pub fn get_receive_address(&self, index: u32) -> Result<DerivedAddress> {
        self.derive_taproot_address(0, false, index)
    }

    pub fn get_change_address(&self, index: u32) -> Result<DerivedAddress> {
        self.derive_taproot_address(0, true, index)
    }

    pub fn get_receive_addresses(&self, count: u32) -> Result<Vec<DerivedAddress>> {
        (0..count).map(|i| self.get_receive_address(i)).collect()
    }

    pub fn master_fingerprint(&self) -> Fingerprint {
        self.master_xpriv.fingerprint(&self.secp)
    }

    pub fn account_xpub(&self, account: u32) -> Result<Xpub> {
        let coin_type = if self.network == Network::Bitcoin {
            0
        } else {
            1
        };

        let path_str = format!("m/86'/{}'/{}'", coin_type, account);
        let path = DerivationPath::from_str(&path_str)
            .map_err(|e| BitcoinError::DerivationPath(format!("Invalid path: {}", e)))?;

        let account_xpriv = self
            .master_xpriv
            .derive_priv(&self.secp, &path)
            .map_err(|e| BitcoinError::DerivationPath(format!("Derivation failed: {}", e)))?;

        Ok(Xpub::from_priv(&self.secp, &account_xpriv))
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_taproot_address() {
        let secret = [1u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();

        let addr = derivation.get_receive_address(0).unwrap();
        assert!(addr.address.to_string().starts_with("tb1p"));

        let addr1 = derivation.get_receive_address(1).unwrap();
        assert_ne!(addr.address, addr1.address);
    }

    #[test]
    fn test_change_addresses() {
        let secret = [2u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Testnet).unwrap();

        let receive = derivation.get_receive_address(0).unwrap();
        let change = derivation.get_change_address(0).unwrap();

        assert_ne!(receive.address, change.address);
    }

    #[test]
    fn test_mainnet_addresses() {
        let secret = [3u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Bitcoin).unwrap();

        let addr = derivation.get_receive_address(0).unwrap();
        assert!(addr.address.to_string().starts_with("bc1p"));
    }

    #[test]
    fn test_fingerprint() {
        let secret = [4u8; 32];
        let derivation = AddressDerivation::new(&secret, Network::Bitcoin).unwrap();

        let fp = derivation.master_fingerprint();
        assert_ne!(fp.to_bytes(), [0u8; 4]);
    }
}
