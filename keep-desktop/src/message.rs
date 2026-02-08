// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use crate::screen::shares::ShareEntry;

#[derive(Debug, Clone)]
pub enum Message {
    // Unlock
    PasswordChanged(String),
    ConfirmPasswordChanged(String),
    Unlock,
    UnlockResult(Result<Vec<ShareEntry>, String>),
    StartFresh,

    // Navigation
    GoToImport,
    GoToExport(usize),
    GoToCreate,
    GoBack,
    Lock,

    // Share list
    RequestDelete(usize),
    ConfirmDelete(usize),
    CancelDelete,

    // Create keyset
    CreateNameChanged(String),
    CreateThresholdChanged(String),
    CreateTotalChanged(String),
    CreateKeyset,
    CreateResult(Result<Vec<ShareEntry>, String>),

    // Export
    ExportPassphraseChanged(String),
    GenerateExport,
    ExportGenerated(Result<String, String>),
    CopyToClipboard(String),

    // Import
    ImportDataChanged(String),
    ImportPassphraseChanged(String),
    ImportShare,
    ImportResult(Result<Vec<ShareEntry>, String>),
}
