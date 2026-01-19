// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod address;
mod descriptor;
mod error;
pub mod psbt;
mod signer;

pub use address::{AddressDerivation, DerivedAddress};
pub use descriptor::DescriptorExport;
pub use error::{BitcoinError, Result};
pub use psbt::{PsbtAnalysis, PsbtSigner};
pub use signer::BitcoinSigner;

pub use bitcoin::Network;
