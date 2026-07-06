// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod address;
pub mod chain_view;
mod descriptor;
mod error;
pub mod key_proof;
pub mod psbt;
pub mod recovery;
pub mod recovery_tx;
mod signer;

pub use address::{AddressDerivation, DerivedAddress};
#[cfg(feature = "esplora-chain-view")]
pub use chain_view::{esplora_chain_view_from_env, EsploraChainView};
pub use chain_view::{
    validate_prevout_amounts_against_chain, ChainView, ChainViewError, KEEP_CHAIN_URL_ENV,
};
pub use descriptor::{
    descriptor_address, descriptor_script_pubkey, multipath_from_external, xpub_to_x_only,
    DescriptorExport,
};
pub use error::{BitcoinError, Result};
pub use key_proof::{build_key_proof_psbt, sign_key_proof, verify_key_proof};
pub use psbt::{PsbtAnalysis, PsbtSigner};
pub use recovery::{
    PolicyInput, PolicyTierInput, RecoveryConfig, RecoveryOutput, RecoveryTier, SpendingTier,
};
pub use recovery_tx::{
    merge_tap_script_sig, script_spend_sighashes, verify_all_script_spend_input_bindings,
    verify_script_spend_input_binding, RecoveryTxBuilder, ScriptSpendSighash, SweepUtxo,
    TAPROOT_DUST_LIMIT_SATS,
};
pub use signer::BitcoinSigner;

pub use bitcoin;
pub use bitcoin::Network;

fn aux_rand() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| BitcoinError::Signing(format!("failed to get random bytes: {e}")))?;
    let wrapped = zeroize::Zeroizing::new(buf);
    zeroize::Zeroize::zeroize(&mut buf);
    Ok(wrapped)
}
