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

/// What `remove_unreadable_share` did. Only `Removed` changed anything, and it
/// set the share aside rather than destroying it.
///
/// `cleared_active_pointer` means this call cleared the active account
/// pointer. A retry after a partial failure can report `false` even though
/// the share was the active account, so callers must re-read the active
/// account after any `Err` and must not treat `false` as "was not active".
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum UnreadableShareRemoval {
    /// Set aside, from where `restore_quarantined_share` puts it back.
    Removed { cleared_active_pointer: bool },
    /// The share can be read now, so it was kept.
    Readable,
    /// The registry lists it unreadable but its stored share still loads, so
    /// its secret is not lost and it was kept.
    Recoverable,
    /// Whether its secret can still be decrypted could not be confirmed, as
    /// when the device was not authenticated, so it was kept.
    Unverified,
    /// No share of this group is stored.
    Absent,
    /// The share registry cannot be read, so whether the share is unreadable
    /// is unknown.
    RegistryUnavailable,
}

/// What `discard_lost_share` did. Only `Discarded` changed anything.
///
/// `cleared_active_pointer` means this call cleared the active account
/// pointer. A retry after a partial failure can report `false` even though
/// the share was the active account, so callers must re-read the active
/// account after any `Err` and must not treat `false` as "was not active".
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum QuarantineDiscard {
    /// Destroyed.
    Discarded { cleared_active_pointer: bool },
    /// Its data decrypts again, so it was kept and should be restored.
    Readable,
    /// Whether its secret is lost could not be confirmed, as when the device
    /// was not authenticated, so it was kept.
    Unverified,
    /// No share of this group is set aside.
    NotSetAside,
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

    /// Store `data` under `key`.
    ///
    /// For a share key (a group public key in hex), when `key` already holds
    /// share data that the share registry does not list, the write must be
    /// refused, unless `metadata` names the same group, share index, threshold
    /// and share count as the stored data, which redoes a write that stopped
    /// before the registry was updated. Listing such data at startup instead
    /// is better still, since core then refuses the write itself. Other
    /// records stored through this method are never in the registry, and the
    /// rule does not apply to them. Core checks for a share it would replace through the
    /// registry alone, so a share left out of it is one only this refusal
    /// keeps from being written over.
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
    /// Set the share under `key` aside without destroying anything. Its
    /// record and key aliases stay where they are, but `read_share_registry`,
    /// `list_all_shares` and the active-share fallback no longer list it, and
    /// `store_share_by_key` refuses to write `key` until it is restored or
    /// deleted. `load_share_by_key` still attempts the real load, so a share
    /// that becomes readable again can be told apart from one that is lost.
    fn quarantine_share_by_key(&self, key: String) -> Result<(), KeepMobileError>;
    /// List the share under `key` again, exactly as it was before
    /// `quarantine_share_by_key`.
    fn restore_quarantined_share(&self, key: String) -> Result<(), KeepMobileError>;
    /// The key of every share set aside and neither restored nor deleted.
    /// `delete_share_by_key` on one of them destroys it and clears the mark.
    /// An `Err` when the set of marks cannot be read, never an empty list.
    fn list_quarantined_share_keys(&self) -> Result<Vec<String>, KeepMobileError>;
    /// Try to decrypt the share under `key` and say what became of it, for
    /// deciding whether a share is lost. Core destroys a share only on
    /// `Lost`, so an implementation must answer `Lost` only on positive
    /// evidence and `Unknown` for every other failure. Core reads an `Err`
    /// as `Unknown`, so throwing never destroys anything.
    fn probe_share_by_key(&self, key: String) -> Result<ShareProbe, KeepMobileError>;
}

/// What `SecureStorage::probe_share_by_key` found.
#[derive(uniffi::Enum)]
pub enum ShareProbe {
    /// The share data, decrypted with the share's own key. It consumes the
    /// request's DECRYPT cipher as a load does. Data that does not validate
    /// as a usable share is never discarded.
    Loads { data: Vec<u8> },
    /// Only on positive evidence that this device can never decrypt it: the
    /// key is permanently invalidated or missing, or the stored ciphertext
    /// fails authentication or is structurally truncated, or the key exists
    /// but the record holds neither IV nor ciphertext, confirmed below any
    /// layer that reads an unloadable record as empty.
    Lost,
    /// Everything else, including no authentication, a cancelled prompt, a
    /// transient fault or anything unclassified.
    Unknown,
}

/// The quarantine and probe methods of a test store that has no quarantine.
#[cfg(test)]
macro_rules! quarantine_unsupported {
    () => {
        fn quarantine_share_by_key(&self, _: String) -> Result<(), $crate::KeepMobileError> {
            Err($crate::KeepMobileError::StorageError {
                msg: "quarantine unsupported".into(),
            })
        }
        fn restore_quarantined_share(&self, _: String) -> Result<(), $crate::KeepMobileError> {
            Err($crate::KeepMobileError::StorageError {
                msg: "quarantine unsupported".into(),
            })
        }
        fn list_quarantined_share_keys(&self) -> Result<Vec<String>, $crate::KeepMobileError> {
            Ok(Vec::new())
        }
        fn probe_share_by_key(
            &self,
            _: String,
        ) -> Result<$crate::storage::ShareProbe, $crate::KeepMobileError> {
            Ok($crate::storage::ShareProbe::Unknown)
        }
    };
}
#[cfg(test)]
pub(crate) use quarantine_unsupported;
