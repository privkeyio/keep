// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::KeepMobileError;

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ShareMetadataInfo {
    pub name: String,
    pub identifier: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: Vec<u8>,
    pub did_backup: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ShareInfo {
    pub name: String,
    pub share_index: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: String,
}

/// A DKG share that completed its ceremony but whose import has not yet been
/// confirmed persisted. Surfaced after relaunch so the app can prompt for the
/// passphrase and finish the import via `recover_dkg_share`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct PendingShareInfo {
    pub name: String,
    pub group_pubkey: String,
    /// `true` when recovery needs only a device-vault unlock (the DKG path stashed
    /// its ephemeral passphrase); `false` when the caller must supply the
    /// passphrase (manual QR import). Lets the UI pick the right recovery prompt.
    pub vault_protected: bool,
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
    pub did_backup: bool,
}

/// The share registry as read, without dropping anything: `Readable` lists the
/// shares that could be read and, in `unreadable`, the storage keys (group
/// pubkey hex) of shares that exist but could not be. `Unavailable` means the
/// registry itself could not be read.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum ShareRegistryRead {
    Readable {
        shares: Vec<ShareMetadataInfo>,
        unreadable: Vec<String>,
    },
    Unavailable,
}

/// Whether every stored share can be read. `SomeUnreadable` lists the group
/// pubkeys (hex) of shares that exist but cannot be read, `Unavailable` means
/// the share registry itself cannot be read.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum ShareStoreStatus {
    Readable,
    SomeUnreadable { group_pubkeys: Vec<String> },
    Unavailable,
}

/// Platform-provided secure storage for encrypted share data and wallet
/// descriptor records.
///
/// Implementations **must** be backed by platform secure storage (iOS
/// Keychain, Android Keystore-backed EncryptedSharedPreferences or
/// equivalent): records persisted through this trait include authentication
/// material (device-returned registration tokens on wallet descriptor
/// records) and FROST share data. Plain-disk file storage is NOT acceptable.
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
    /// Read the record under `key`.
    ///
    /// Absence and failure are different answers and an implementation must
    /// not collapse them. `StorageNotFound` means there is no record. A record
    /// that exists and could not be produced, because it would not decrypt,
    /// because a key alias was invalidated, or because only part of it is
    /// there, must come back as some other `Err`.
    ///
    /// This is load bearing rather than tidiness. Callers that hold a record
    /// unreadable are built to refuse rather than to proceed: no policy means
    /// no rules, and no spending history means nothing spent, so an
    /// implementation that reports an unreadable record as absent turns a
    /// refusal into exactly the permission it was there to withhold.
    fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError>;
    fn list_all_shares(&self) -> Vec<ShareMetadataInfo>;
    /// Read the share registry as it is: `Readable` with every share that could
    /// be read and, under `unreadable`, the key of every share that exists but
    /// could not be, `Unavailable` when the registry itself cannot be read. A
    /// share must never be dropped silently. A registry entry with no record
    /// stored behind it is absent, not unreadable. No fallback and no side
    /// effect, and it must not throw: a fault reading the registry is
    /// `Unavailable`.
    ///
    /// Callers that count shares or build a backup rely on the difference:
    /// taking an unreadable share for an absent one undercounts the store and
    /// produces a backup that is missing it.
    fn read_share_registry(&self) -> ShareRegistryRead;
    /// Delete the record under `key`.
    ///
    /// Callers must not read an `Err` as "nothing was removed". An
    /// implementation that destroys the record and then fails a later step, for
    /// example clearing the stored bytes before dropping a key alias or
    /// rewriting an index, reports failure for a record that is already gone,
    /// so anything holding that record in memory has to be torn down on the
    /// error path too.
    fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError>;
    fn get_active_share_key(&self) -> Option<String>;
    /// Read the stored active-share pointer as it is: `Found` with the key it
    /// holds (even one naming a share since deleted), `Absent` when no pointer
    /// is stored, `Unavailable` when it is present but cannot be read or the
    /// lookup cannot complete. No fallback, no inference from the shares
    /// listed, and no side effect: unlike `get_active_share_key`, which may
    /// resolve and store a fallback, this must not write.
    ///
    /// Callers that decide whether to set or clear the pointer rely on the
    /// difference: taking a failed read for an unset pointer switches the
    /// active account without the cleanup a switch needs.
    fn read_active_share_key(&self) -> crate::signing_policy::StorageRead;
    fn set_active_share_key(&self, key: Option<String>) -> Result<(), KeepMobileError>;
}
