// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod address;
mod descriptor;
mod error;
pub mod psbt;
pub mod recovery;
pub mod recovery_tx;
mod signer;

pub use address::{AddressDerivation, DerivedAddress};
pub use descriptor::{xpub_to_x_only, DescriptorExport};
pub use error::{BitcoinError, Result};
pub use psbt::{PsbtAnalysis, PsbtSigner};
pub use recovery::{
    PolicyInput, PolicyTierInput, RecoveryConfig, RecoveryOutput, RecoveryTier, SpendingTier,
};
pub use recovery_tx::RecoveryTxBuilder;
pub use signer::BitcoinSigner;

pub use bitcoin::Network;

fn aux_rand() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)
        .map_err(|e| BitcoinError::Signing(format!("failed to get random bytes: {e}")))?;
    let wrapped = zeroize::Zeroizing::new(buf);
    zeroize::Zeroize::zeroize(&mut buf);
    Ok(wrapped)
}
