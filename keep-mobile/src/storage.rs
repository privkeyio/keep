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

#[derive(uniffi::Record, Clone, Debug)]
pub struct StoredShareInfo {
    pub group_pubkey: String,
    pub name: String,
    pub share_index: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub sign_count: u64,
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

    fn store_share_by_key(
        &self,
        key: String,
        data: Vec<u8>,
        metadata: ShareMetadataInfo,
    ) -> Result<(), KeepMobileError>;
    fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError>;
    fn list_all_shares(&self) -> Vec<ShareMetadataInfo>;
    fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError>;
    fn get_active_share_key(&self) -> Option<String>;
    fn set_active_share_key(&self, key: Option<String>) -> Result<(), KeepMobileError>;
}
