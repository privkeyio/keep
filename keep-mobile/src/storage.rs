// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::KeepMobileError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct ShareMetadataInfo {
    pub name: String,
    pub identifier: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ShareInfo {
    pub name: String,
    pub share_index: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: String,
}

#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    fn store_share(
        &self,
        data: Vec<u8>,
        metadata: ShareMetadataInfo,
    ) -> Result<(), KeepMobileError>;
    fn load_share(&self) -> Result<Vec<u8>, KeepMobileError>;
    fn has_share(&self) -> bool;
    fn get_share_metadata(&self) -> Option<ShareMetadataInfo>;
    fn delete_share(&self) -> Result<(), KeepMobileError>;
}
