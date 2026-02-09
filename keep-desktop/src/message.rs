// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use zeroize::Zeroizing;

use crate::screen::shares::ShareEntry;

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
    GenerateExport,
    ExportGenerated(Result<ExportData, String>),
    AdvanceQrFrame,
    CopyToClipboard(Zeroizing<String>),
    ResetExport,

    // Import
    ImportDataChanged(Zeroizing<String>),
    ImportPassphraseChanged(Zeroizing<String>),
    ImportShare,
    ImportResult(Result<Vec<ShareEntry>, String>),

    // Timer
    Tick,
}

#[derive(Debug, Clone)]
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
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::Tick => f.write_str("Tick"),
        }
    }
}
