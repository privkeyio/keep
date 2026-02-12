// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use zeroize::Zeroizing;

use crate::screen::relays::RelayShareEntry;
use crate::screen::shares::ShareEntry;
use crate::screen::wallet::WalletEntry;

#[derive(Clone)]
pub struct ExportData {
    pub bech32: Zeroizing<String>,
    pub frames: Vec<Zeroizing<String>>,
}

#[derive(Clone)]
pub enum Message {
    // Unlock
    PasswordChanged(Zeroizing<String>),
    ConfirmPasswordChanged(Zeroizing<String>),
    Unlock,
    UnlockResult(Result<Vec<ShareEntry>, String>),
    StartFresh,
    ConfirmStartFresh,
    StartFreshResult(Result<(), String>),
    CancelStartFresh,

    // Navigation
    GoToImport,
    GoToExport(usize),
    GoToCreate,
    GoBack,
    NavigateShares,
    NavigateWallets,
    Lock,

    // Share list
    ToggleShareDetails(usize),
    RequestDelete(ShareIdentity),
    ConfirmDelete(ShareIdentity),
    CancelDelete,

    // Create keyset
    CreateNameChanged(String),
    CreateThresholdChanged(String),
    CreateTotalChanged(String),
    CreateKeyset,
    CreateResult(Result<Vec<ShareEntry>, String>),

    // Export
    ExportPassphraseChanged(Zeroizing<String>),
    ExportConfirmPassphraseChanged(Zeroizing<String>),
    GenerateExport,
    ExportGenerated(Result<ExportData, String>),
    AdvanceQrFrame,
    CopyToClipboard(Zeroizing<String>),
    ResetExport,

    // Import
    ImportDataChanged(Zeroizing<String>),
    ImportPassphraseChanged(Zeroizing<String>),
    ImportShare,
    ImportResult(Result<(Vec<ShareEntry>, String), String>),

    // Clipboard (public data, no auto-clear)
    CopyNpub(String),
    CopyDescriptor(String),

    // Wallets
    ToggleWalletDetails(usize),
    WalletsLoaded(Result<Vec<WalletEntry>, String>),

    // Relays
    NavigateRelays,
    RelaysLoaded(Result<Vec<RelayShareEntry>, String>),
    ToggleRelayDetails(usize),
    FrostRelayInputChanged(String),
    ProfileRelayInputChanged(String),
    AddFrostRelay(usize),
    AddProfileRelay(usize),
    RemoveFrostRelay(usize, String),
    RemoveProfileRelay(usize, String),
    RelaySaved(Result<Vec<RelayShareEntry>, String>),

    // Timer
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareIdentity {
    pub group_pubkey: [u8; 32],
    pub identifier: u16,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordChanged(_) => f.write_str("PasswordChanged(***)"),
            Self::ConfirmPasswordChanged(_) => f.write_str("ConfirmPasswordChanged(***)"),
            Self::ExportPassphraseChanged(_) => f.write_str("ExportPassphraseChanged(***)"),
            Self::ExportConfirmPassphraseChanged(_) => {
                f.write_str("ExportConfirmPassphraseChanged(***)")
            }
            Self::ImportPassphraseChanged(_) => f.write_str("ImportPassphraseChanged(***)"),
            Self::ImportDataChanged(_) => f.write_str("ImportDataChanged(***)"),
            Self::ExportGenerated(_) => f.write_str("ExportGenerated(***)"),
            Self::CopyToClipboard(_) => f.write_str("CopyToClipboard(***)"),
            Self::Unlock => f.write_str("Unlock"),
            Self::UnlockResult(r) => f
                .debug_tuple("UnlockResult")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::StartFresh => f.write_str("StartFresh"),
            Self::ConfirmStartFresh => f.write_str("ConfirmStartFresh"),
            Self::StartFreshResult(_) => f.write_str("StartFreshResult(***)"),
            Self::CancelStartFresh => f.write_str("CancelStartFresh"),
            Self::GoToImport => f.write_str("GoToImport"),
            Self::GoToExport(i) => f.debug_tuple("GoToExport").field(i).finish(),
            Self::GoToCreate => f.write_str("GoToCreate"),
            Self::GoBack => f.write_str("GoBack"),
            Self::NavigateShares => f.write_str("NavigateShares"),
            Self::NavigateWallets => f.write_str("NavigateWallets"),
            Self::Lock => f.write_str("Lock"),
            Self::ToggleShareDetails(i) => f.debug_tuple("ToggleShareDetails").field(i).finish(),
            Self::RequestDelete(id) => f.debug_tuple("RequestDelete").field(id).finish(),
            Self::ConfirmDelete(id) => f.debug_tuple("ConfirmDelete").field(id).finish(),
            Self::CancelDelete => f.write_str("CancelDelete"),
            Self::CreateNameChanged(n) => f.debug_tuple("CreateNameChanged").field(n).finish(),
            Self::CreateThresholdChanged(t) => {
                f.debug_tuple("CreateThresholdChanged").field(t).finish()
            }
            Self::CreateTotalChanged(t) => f.debug_tuple("CreateTotalChanged").field(t).finish(),
            Self::CreateKeyset => f.write_str("CreateKeyset"),
            Self::CreateResult(r) => f
                .debug_tuple("CreateResult")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::GenerateExport => f.write_str("GenerateExport"),
            Self::AdvanceQrFrame => f.write_str("AdvanceQrFrame"),
            Self::ResetExport => f.write_str("ResetExport"),
            Self::ImportShare => f.write_str("ImportShare"),
            Self::ImportResult(r) => f
                .debug_tuple("ImportResult")
                .field(&r.as_ref().map(|(v, _)| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::CopyNpub(n) => f.debug_tuple("CopyNpub").field(n).finish(),
            Self::CopyDescriptor(d) => f.debug_tuple("CopyDescriptor").field(d).finish(),
            Self::ToggleWalletDetails(i) => f.debug_tuple("ToggleWalletDetails").field(i).finish(),
            Self::WalletsLoaded(r) => f
                .debug_tuple("WalletsLoaded")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::NavigateRelays => f.write_str("NavigateRelays"),
            Self::RelaysLoaded(r) => f
                .debug_tuple("RelaysLoaded")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::ToggleRelayDetails(i) => f.debug_tuple("ToggleRelayDetails").field(i).finish(),
            Self::FrostRelayInputChanged(s) => {
                f.debug_tuple("FrostRelayInputChanged").field(s).finish()
            }
            Self::ProfileRelayInputChanged(s) => {
                f.debug_tuple("ProfileRelayInputChanged").field(s).finish()
            }
            Self::AddFrostRelay(i) => f.debug_tuple("AddFrostRelay").field(i).finish(),
            Self::AddProfileRelay(i) => f.debug_tuple("AddProfileRelay").field(i).finish(),
            Self::RemoveFrostRelay(i, r) => {
                f.debug_tuple("RemoveFrostRelay").field(i).field(r).finish()
            }
            Self::RemoveProfileRelay(i, r) => f
                .debug_tuple("RemoveProfileRelay")
                .field(i)
                .field(r)
                .finish(),
            Self::RelaySaved(r) => f
                .debug_tuple("RelaySaved")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::Tick => f.write_str("Tick"),
        }
    }
}
