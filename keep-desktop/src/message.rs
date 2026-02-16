// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use zeroize::Zeroizing;

use crate::screen::shares::ShareEntry;
use crate::screen::signing_audit::AuditDisplayEntry;
use crate::screen::wallet::WalletEntry;

#[derive(Clone, Debug, PartialEq)]
pub enum IdentityKind {
    Frost {
        threshold: u16,
        total_shares: u16,
        share_count: usize,
    },
    Nsec,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub pubkey_hex: String,
    pub npub: String,
    pub name: String,
    pub kind: IdentityKind,
}

impl Identity {
    pub fn truncated_npub(&self) -> String {
        if !self.npub.is_ascii() || self.npub.len() <= 20 {
            return self.npub.clone();
        }
        format!(
            "{}...{}",
            &self.npub[..12],
            &self.npub[self.npub.len() - 6..]
        )
    }
}

#[derive(Clone)]
pub struct AuditLoadResult {
    pub entries: Vec<AuditDisplayEntry>,
    pub callers: Vec<String>,
    pub count: usize,
    pub has_more: bool,
}

#[derive(Clone)]
pub struct ExportData {
    pub bech32: Zeroizing<String>,
    pub frames: Vec<Zeroizing<String>>,
}

#[derive(Clone, Debug)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub share_index: u16,
    pub name: Option<String>,
    pub online: bool,
}

#[derive(Clone, Debug)]
pub struct PendingSignRequest {
    pub id: String,
    pub message_preview: String,
    pub from_peer: u16,
    pub timestamp: u64,
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
    NavigateRelay,
    NavigateBunker,
    NavigateSettings,
    Lock,

    // Share list
    ToggleShareDetails(usize),
    SetActiveShare(String),
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

    // Export ncryptsec
    GoToExportNcryptsec(String),
    ExportNcryptsecPasswordChanged(Zeroizing<String>),
    ExportNcryptsecConfirmChanged(Zeroizing<String>),
    GenerateNcryptsec,
    NcryptsecGenerated(Result<ExportData, String>),
    ResetNcryptsec,

    // Import
    ImportDataChanged(Zeroizing<String>),
    ImportPassphraseChanged(Zeroizing<String>),
    ImportNameChanged(String),
    ImportToggleVisibility,
    ImportShare,
    ImportNsec,
    ImportNcryptsec,
    ImportResult(Result<(Vec<ShareEntry>, String), String>),
    ImportNsecResult(Result<(Vec<ShareEntry>, String), String>),
    ImportNcryptsecResult(Result<(Vec<ShareEntry>, String), String>),

    // Scanner
    ScannerOpen,
    ScannerClose,
    ScannerRetry,
    ScannerPoll,

    // Clipboard (public data, no auto-clear)
    CopyNpub(String),
    CopyDescriptor(String),

    // Wallets
    ToggleWalletDetails(usize),
    WalletsLoaded(Result<Vec<WalletEntry>, String>),

    // Relay / FROST
    RelayUrlChanged(String),
    ConnectPasswordChanged(Zeroizing<String>),
    AddRelay,
    RemoveRelay(usize),
    SelectShareForRelay(usize),
    ConnectRelay,
    DisconnectRelay,
    ConnectRelayResult(Result<(), String>),
    ApproveSignRequest(String),
    RejectSignRequest(String),

    // Bunker
    BunkerRelayInputChanged(String),
    BunkerAddRelay,
    BunkerRemoveRelay(usize),
    BunkerStart,
    BunkerStartResult(Result<String, String>),
    BunkerStop,
    BunkerApprove,
    BunkerReject,
    BunkerRevokeClient(usize),
    BunkerConfirmRevokeAll,
    BunkerCancelRevokeAll,
    BunkerRevokeAll,
    BunkerCopyUrl,
    BunkerRevokeResult(Result<(), String>),
    BunkerClientsLoaded(Vec<crate::screen::bunker::ConnectedClient>),
    BunkerToggleClient(usize),
    BunkerTogglePermission(usize, u32),
    BunkerSetApprovalDuration(usize),
    BunkerPermissionUpdated(Result<(), String>),

    // Signing Audit
    NavigateAudit,
    AuditLoaded(Result<AuditLoadResult, String>),
    AuditPageLoaded(Result<AuditLoadResult, String>),
    AuditChainVerified(Result<(bool, usize), String>),
    AuditFilterChanged(Option<String>),
    AuditLoadMore,

    // Identity
    ToggleIdentitySwitcher,
    SwitchIdentity(String),
    RequestDeleteIdentity(String),
    ConfirmDeleteIdentity(String),
    CancelDeleteIdentity,

    // Settings
    SettingsAutoLockChanged(u64),
    SettingsClipboardClearChanged(u64),
    SettingsProxyToggled(bool),
    SettingsProxyPortChanged(String),
    SettingsMinimizeToTrayToggled(bool),
    SettingsStartMinimizedToggled(bool),

    // Window
    WindowCloseRequested(iced::window::Id),

    // Kill switch
    KillSwitchRequestConfirm,
    KillSwitchCancelConfirm,
    KillSwitchActivate,
    KillSwitchPasswordChanged(Zeroizing<String>),
    KillSwitchDeactivate,
    KillSwitchDeactivateResult(Result<(), String>),

    // Timer
    Tick,
}

#[derive(Clone, Debug)]
pub enum FrostNodeMsg {
    PeerUpdate(Vec<PeerEntry>),
    NewSignRequest(PendingSignRequest),
    SignRequestRemoved(String),
    StatusChanged(ConnectionStatus),
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
            Self::NavigateRelay => f.write_str("NavigateRelay"),
            Self::NavigateBunker => f.write_str("NavigateBunker"),
            Self::NavigateSettings => f.write_str("NavigateSettings"),
            Self::Lock => f.write_str("Lock"),
            Self::ToggleShareDetails(i) => f.debug_tuple("ToggleShareDetails").field(i).finish(),
            Self::SetActiveShare(k) => f.debug_tuple("SetActiveShare").field(k).finish(),
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
            Self::GoToExportNcryptsec(k) => {
                f.debug_tuple("GoToExportNcryptsec").field(k).finish()
            }
            Self::ExportNcryptsecPasswordChanged(_) => {
                f.write_str("ExportNcryptsecPasswordChanged(***)")
            }
            Self::ExportNcryptsecConfirmChanged(_) => {
                f.write_str("ExportNcryptsecConfirmChanged(***)")
            }
            Self::GenerateNcryptsec => f.write_str("GenerateNcryptsec"),
            Self::NcryptsecGenerated(_) => f.write_str("NcryptsecGenerated(***)"),
            Self::ResetNcryptsec => f.write_str("ResetNcryptsec"),
            Self::ImportNameChanged(n) => f.debug_tuple("ImportNameChanged").field(n).finish(),
            Self::ImportToggleVisibility => f.write_str("ImportToggleVisibility"),
            Self::ImportShare => f.write_str("ImportShare"),
            Self::ImportNsec => f.write_str("ImportNsec"),
            Self::ImportNcryptsec => f.write_str("ImportNcryptsec"),
            Self::ImportResult(r) => f
                .debug_tuple("ImportResult")
                .field(&r.as_ref().map(|(v, _)| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::ImportNsecResult(r) => f
                .debug_tuple("ImportNsecResult")
                .field(&r.as_ref().map(|(v, _)| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::ImportNcryptsecResult(r) => f
                .debug_tuple("ImportNcryptsecResult")
                .field(&r.as_ref().map(|(v, _)| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::CopyNpub(n) => f.debug_tuple("CopyNpub").field(n).finish(),
            Self::CopyDescriptor(d) => f.debug_tuple("CopyDescriptor").field(d).finish(),
            Self::ToggleWalletDetails(i) => f.debug_tuple("ToggleWalletDetails").field(i).finish(),
            Self::WalletsLoaded(r) => f
                .debug_tuple("WalletsLoaded")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::RelayUrlChanged(u) => f.debug_tuple("RelayUrlChanged").field(u).finish(),
            Self::ConnectPasswordChanged(_) => f.write_str("ConnectPasswordChanged(***)"),
            Self::AddRelay => f.write_str("AddRelay"),
            Self::RemoveRelay(i) => f.debug_tuple("RemoveRelay").field(i).finish(),
            Self::SelectShareForRelay(i) => f.debug_tuple("SelectShareForRelay").field(i).finish(),
            Self::ConnectRelay => f.write_str("ConnectRelay"),
            Self::DisconnectRelay => f.write_str("DisconnectRelay"),
            Self::ConnectRelayResult(r) => f
                .debug_tuple("ConnectRelayResult")
                .field(&r.as_ref().map(|_| ()).map_err(|e| e.as_str()))
                .finish(),
            Self::ApproveSignRequest(id) => f.debug_tuple("ApproveSignRequest").field(id).finish(),
            Self::RejectSignRequest(id) => f.debug_tuple("RejectSignRequest").field(id).finish(),
            Self::BunkerRelayInputChanged(_) => f.write_str("BunkerRelayInputChanged"),
            Self::BunkerAddRelay => f.write_str("BunkerAddRelay"),
            Self::BunkerRemoveRelay(i) => f.debug_tuple("BunkerRemoveRelay").field(i).finish(),
            Self::BunkerStart => f.write_str("BunkerStart"),
            Self::BunkerStartResult(r) => f
                .debug_tuple("BunkerStartResult")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| e.as_str()))
                .finish(),
            Self::BunkerStop => f.write_str("BunkerStop"),
            Self::BunkerApprove => f.write_str("BunkerApprove"),
            Self::BunkerReject => f.write_str("BunkerReject"),
            Self::BunkerRevokeClient(i) => f.debug_tuple("BunkerRevokeClient").field(i).finish(),
            Self::BunkerConfirmRevokeAll => f.write_str("BunkerConfirmRevokeAll"),
            Self::BunkerCancelRevokeAll => f.write_str("BunkerCancelRevokeAll"),
            Self::BunkerRevokeAll => f.write_str("BunkerRevokeAll"),
            Self::BunkerCopyUrl => f.write_str("BunkerCopyUrl"),
            Self::BunkerRevokeResult(_) => f.write_str("BunkerRevokeResult"),
            Self::BunkerClientsLoaded(c) => f
                .debug_tuple("BunkerClientsLoaded")
                .field(&c.len())
                .finish(),
            Self::BunkerToggleClient(i) => f.debug_tuple("BunkerToggleClient").field(i).finish(),
            Self::BunkerTogglePermission(i, f2) => f
                .debug_tuple("BunkerTogglePermission")
                .field(i)
                .field(f2)
                .finish(),
            Self::BunkerSetApprovalDuration(i) => {
                f.debug_tuple("BunkerSetApprovalDuration").field(i).finish()
            }
            Self::BunkerPermissionUpdated(_) => f.write_str("BunkerPermissionUpdated"),
            Self::ToggleIdentitySwitcher => f.write_str("ToggleIdentitySwitcher"),
            Self::SwitchIdentity(k) => f.debug_tuple("SwitchIdentity").field(k).finish(),
            Self::RequestDeleteIdentity(k) => {
                f.debug_tuple("RequestDeleteIdentity").field(k).finish()
            }
            Self::ConfirmDeleteIdentity(k) => {
                f.debug_tuple("ConfirmDeleteIdentity").field(k).finish()
            }
            Self::CancelDeleteIdentity => f.write_str("CancelDeleteIdentity"),
            Self::SettingsAutoLockChanged(v) => {
                f.debug_tuple("SettingsAutoLockChanged").field(v).finish()
            }
            Self::SettingsClipboardClearChanged(v) => f
                .debug_tuple("SettingsClipboardClearChanged")
                .field(v)
                .finish(),
            Self::SettingsProxyToggled(v) => {
                f.debug_tuple("SettingsProxyToggled").field(v).finish()
            }
            Self::SettingsProxyPortChanged(v) => {
                f.debug_tuple("SettingsProxyPortChanged").field(v).finish()
            }
            Self::NavigateAudit => f.write_str("NavigateAudit"),
            Self::AuditLoaded(r) => f
                .debug_tuple("AuditLoaded")
                .field(&r.as_ref().map(|v| v.entries.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::AuditPageLoaded(r) => f
                .debug_tuple("AuditPageLoaded")
                .field(&r.as_ref().map(|v| v.entries.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::AuditChainVerified(r) => f
                .debug_tuple("AuditChainVerified")
                .field(&r.as_ref().map(|(v, c)| (*v, *c)).map_err(|e| e.as_str()))
                .finish(),
            Self::AuditFilterChanged(c) => f.debug_tuple("AuditFilterChanged").field(c).finish(),
            Self::AuditLoadMore => f.write_str("AuditLoadMore"),
            Self::KillSwitchRequestConfirm => f.write_str("KillSwitchRequestConfirm"),
            Self::KillSwitchCancelConfirm => f.write_str("KillSwitchCancelConfirm"),
            Self::KillSwitchActivate => f.write_str("KillSwitchActivate"),
            Self::KillSwitchPasswordChanged(_) => f.write_str("KillSwitchPasswordChanged(***)"),
            Self::KillSwitchDeactivate => f.write_str("KillSwitchDeactivate"),
            Self::KillSwitchDeactivateResult(r) => f
                .debug_tuple("KillSwitchDeactivateResult")
                .field(&r.as_ref().map(|_| ()).map_err(|e| e.as_str()))
                .finish(),
            Self::SettingsMinimizeToTrayToggled(v) => f
                .debug_tuple("SettingsMinimizeToTrayToggled")
                .field(v)
                .finish(),
            Self::SettingsStartMinimizedToggled(v) => f
                .debug_tuple("SettingsStartMinimizedToggled")
                .field(v)
                .finish(),
            Self::WindowCloseRequested(_) => f.write_str("WindowCloseRequested"),
            Self::ScannerOpen => f.write_str("ScannerOpen"),
            Self::ScannerClose => f.write_str("ScannerClose"),
            Self::ScannerRetry => f.write_str("ScannerRetry"),
            Self::ScannerPoll => f.write_str("ScannerPoll"),
            Self::Tick => f.write_str("Tick"),
        }
    }
}
