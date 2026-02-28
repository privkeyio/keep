// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use keep_frost_net::AnnouncedXpub;
use zeroize::Zeroizing;

use crate::screen::shares::ShareEntry;
use crate::screen::signing_audit::AuditDisplayEntry;
use crate::screen::truncate_npub;
use crate::screen::wallet::{DescriptorProgress, WalletEntry};

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
        truncate_npub(&self.npub)
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
pub struct PinMismatchInfo {
    pub hostname: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug)]
pub enum ConnectionError {
    PinMismatch(PinMismatchInfo),
    Other(String),
}

impl From<String> for ConnectionError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PinMismatch(info) => write!(
                f,
                "Certificate pin mismatch for {}: expected {}, got {}",
                info.hostname, info.expected, info.actual
            ),
            Self::Other(msg) => f.write_str(msg),
        }
    }
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
    Unlock(crate::screen::unlock::Message),
    UnlockResult(Result<Vec<ShareEntry>, String>),
    StartFreshResult(Result<(), String>),

    // Navigation
    GoToImport,
    GoToExport(usize),
    GoToCreate,
    GoBack,
    NavigateShares,
    NavigateNsecKeys,
    NavigateWallets,
    NavigateRelay,
    NavigateBunker,
    NavigateSettings,
    Lock,

    // Share list
    ShareList(crate::screen::shares::Message),

    // Nsec keys list
    NsecKeys(crate::screen::nsec_keys::Message),

    // Create keyset
    Create(crate::screen::create::Message),
    CreateResult(Result<Vec<ShareEntry>, String>),

    // Export
    Export(crate::screen::export::Message),
    ExportGenerated(Result<ExportData, String>),

    // Export ncryptsec
    GoToExportNcryptsec(String),
    ExportNcryptsec(crate::screen::export_ncryptsec::Message),
    NcryptsecGenerated(Result<ExportData, String>),

    // Import
    Import(crate::screen::import::Message),
    ImportResult(Result<(Vec<ShareEntry>, String), String>),
    ImportNsecResult(Result<(Vec<ShareEntry>, String), String>),
    ImportNcryptsecResult(Result<(Vec<ShareEntry>, String), String>),

    // Scanner
    Scanner(crate::screen::scanner::Message),
    ScannerPoll,

    // Wallets
    Wallet(crate::screen::wallet::Message),
    WalletsLoaded(Result<Vec<WalletEntry>, String>),
    WalletSessionStarted(Result<([u8; 32], [u8; 32], String, usize), String>),
    WalletDescriptorProgress(DescriptorProgress, Option<[u8; 32]>),
    WalletAnnounceResult(Result<(), String>),

    // Relay / FROST
    Relay(crate::screen::relay::Message),
    ConnectRelayResult(Result<(), ConnectionError>),

    // Bunker
    Bunker(crate::screen::bunker::Message),
    BunkerStartResult(Result<String, ConnectionError>),
    BunkerRevokeResult(Result<(), String>),
    BunkerClientsLoaded(Vec<crate::screen::bunker::ConnectedClient>),
    BunkerPermissionUpdated(Result<(), String>),

    // Signing Audit
    NavigateAudit,
    SigningAudit(crate::screen::signing_audit::Message),
    AuditLoaded(Result<AuditLoadResult, String>),
    AuditPageLoaded(Result<AuditLoadResult, String>),
    AuditChainVerified(Result<(bool, usize), String>),

    // Identity
    ToggleIdentitySwitcher,
    SwitchIdentity(String),
    RequestDeleteIdentity(String),
    ConfirmDeleteIdentity(String),
    CancelDeleteIdentity,

    // Settings
    Settings(crate::screen::settings::Message),

    // Backup / Restore
    BackupResult(Result<String, String>),
    RestoreFileLoaded(String, Vec<u8>),
    RestoreResult(Result<String, String>),

    // Certificate pinning (modal overlay, not screen-local)
    CertPinMismatchDismiss,
    CertPinMismatchClearAndRetry,
    CertPinMismatchConfirmClear,

    // Window
    WindowCloseRequested(iced::window::Id),

    // Kill switch
    KillSwitchDeactivateResult(Result<(), String>),

    // Timer
    Tick,
}

#[derive(Clone)]
pub enum FrostNodeMsg {
    PeerUpdate(Vec<PeerEntry>),
    NewSignRequest(PendingSignRequest),
    SignRequestRemoved(String),
    StatusChanged(ConnectionStatus),
    DescriptorContributionNeeded {
        session_id: [u8; 32],
        network: String,
        initiator_pubkey: nostr_sdk::PublicKey,
    },
    DescriptorContributed {
        session_id: [u8; 32],
        share_index: u16,
    },
    DescriptorReady {
        session_id: [u8; 32],
    },
    DescriptorComplete {
        session_id: [u8; 32],
        external_descriptor: String,
        internal_descriptor: String,
    },
    DescriptorAcked {
        session_id: [u8; 32],
        share_index: u16,
        ack_count: usize,
        expected_acks: usize,
    },
    DescriptorNacked {
        session_id: [u8; 32],
        share_index: u16,
        reason: String,
    },
    DescriptorFailed {
        session_id: [u8; 32],
        error: String,
    },
    XpubAnnounced {
        share_index: u16,
        recovery_xpubs: Vec<AnnouncedXpub>,
    },
    HealthCheckComplete {
        responsive: Vec<u16>,
        unresponsive: Vec<u16>,
    },
}

impl fmt::Debug for FrostNodeMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUpdate(peers) => f.debug_tuple("PeerUpdate").field(&peers.len()).finish(),
            Self::NewSignRequest(_) => f.write_str("NewSignRequest"),
            Self::SignRequestRemoved(id) => f.debug_tuple("SignRequestRemoved").field(id).finish(),
            Self::StatusChanged(s) => f.debug_tuple("StatusChanged").field(s).finish(),
            Self::DescriptorContributionNeeded { session_id, .. } => f
                .debug_struct("DescriptorContributionNeeded")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorContributed {
                session_id,
                share_index,
            } => f
                .debug_struct("DescriptorContributed")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .finish(),
            Self::DescriptorReady { session_id } => f
                .debug_struct("DescriptorReady")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::DescriptorComplete { session_id, .. } => f
                .debug_struct("DescriptorComplete")
                .field("session_id", &hex::encode(session_id))
                .field("external_descriptor", &"***")
                .field("internal_descriptor", &"***")
                .finish(),
            Self::DescriptorAcked {
                session_id,
                share_index,
                ack_count,
                expected_acks,
            } => f
                .debug_struct("DescriptorAcked")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .field("ack_count", ack_count)
                .field("expected_acks", expected_acks)
                .finish(),
            Self::DescriptorNacked {
                session_id,
                share_index,
                reason,
            } => f
                .debug_struct("DescriptorNacked")
                .field("session_id", &hex::encode(session_id))
                .field("share_index", share_index)
                .field("reason", reason)
                .finish(),
            Self::DescriptorFailed { session_id, error } => f
                .debug_struct("DescriptorFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::XpubAnnounced {
                share_index,
                recovery_xpubs,
            } => f
                .debug_struct("XpubAnnounced")
                .field("share_index", share_index)
                .field("xpub_count", &recovery_xpubs.len())
                .finish(),
            Self::HealthCheckComplete {
                responsive,
                unresponsive,
            } => f
                .debug_struct("HealthCheckComplete")
                .field("responsive", &responsive.len())
                .field("unresponsive", &unresponsive.len())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareIdentity {
    pub group_pubkey: [u8; 32],
    pub identifier: u16,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlock(msg) => f.debug_tuple("Unlock").field(msg).finish(),
            Self::Export(msg) => f.debug_tuple("Export").field(msg).finish(),
            Self::ExportNcryptsec(msg) => f.debug_tuple("ExportNcryptsec").field(msg).finish(),
            Self::Import(msg) => f.debug_tuple("Import").field(msg).finish(),
            Self::ExportGenerated(_) => f.write_str("ExportGenerated(***)"),
            Self::UnlockResult(r) => f
                .debug_tuple("UnlockResult")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::StartFreshResult(_) => f.write_str("StartFreshResult(***)"),
            Self::GoToImport => f.write_str("GoToImport"),
            Self::GoToExport(i) => f.debug_tuple("GoToExport").field(i).finish(),
            Self::GoToCreate => f.write_str("GoToCreate"),
            Self::GoBack => f.write_str("GoBack"),
            Self::NavigateShares => f.write_str("NavigateShares"),
            Self::NavigateNsecKeys => f.write_str("NavigateNsecKeys"),
            Self::NavigateWallets => f.write_str("NavigateWallets"),
            Self::NavigateRelay => f.write_str("NavigateRelay"),
            Self::NavigateBunker => f.write_str("NavigateBunker"),
            Self::NavigateSettings => f.write_str("NavigateSettings"),
            Self::Lock => f.write_str("Lock"),
            Self::ShareList(msg) => f.debug_tuple("ShareList").field(msg).finish(),
            Self::NsecKeys(msg) => f.debug_tuple("NsecKeys").field(msg).finish(),
            Self::Create(msg) => f.debug_tuple("Create").field(msg).finish(),
            Self::CreateResult(r) => f
                .debug_tuple("CreateResult")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::GoToExportNcryptsec(k) => f.debug_tuple("GoToExportNcryptsec").field(k).finish(),
            Self::NcryptsecGenerated(_) => f.write_str("NcryptsecGenerated(***)"),
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
            Self::Wallet(msg) => f.debug_tuple("Wallet").field(msg).finish(),
            Self::WalletsLoaded(r) => f
                .debug_tuple("WalletsLoaded")
                .field(&r.as_ref().map(|v| v.len()).map_err(|e| e.as_str()))
                .finish(),
            Self::WalletSessionStarted(r) => f
                .debug_tuple("WalletSessionStarted")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| e.as_str()))
                .finish(),
            Self::WalletDescriptorProgress(..) => f.write_str("WalletDescriptorProgress"),
            Self::WalletAnnounceResult(r) => f
                .debug_tuple("WalletAnnounceResult")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| e.as_str()))
                .finish(),
            Self::Relay(msg) => f.debug_tuple("Relay").field(msg).finish(),
            Self::ConnectRelayResult(r) => f
                .debug_tuple("ConnectRelayResult")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| format!("{e}")))
                .finish(),
            Self::Bunker(msg) => f.debug_tuple("Bunker").field(msg).finish(),
            Self::BunkerStartResult(r) => f
                .debug_tuple("BunkerStartResult")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| format!("{e}")))
                .finish(),
            Self::BunkerRevokeResult(_) => f.write_str("BunkerRevokeResult"),
            Self::BunkerClientsLoaded(c) => f
                .debug_tuple("BunkerClientsLoaded")
                .field(&c.len())
                .finish(),
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
            Self::Settings(msg) => f.debug_tuple("Settings").field(msg).finish(),
            Self::BackupResult(r) => f
                .debug_tuple("BackupResult")
                .field(&r.as_ref().map(|p| p.as_str()).map_err(|e| e.as_str()))
                .finish(),
            Self::RestoreFileLoaded(name, data) => f
                .debug_tuple("RestoreFileLoaded")
                .field(name)
                .field(&data.len())
                .finish(),
            Self::RestoreResult(r) => f
                .debug_tuple("RestoreResult")
                .field(&r.as_ref().map(|_| "ok").map_err(|e| e.as_str()))
                .finish(),
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
            Self::SigningAudit(msg) => f.debug_tuple("SigningAudit").field(msg).finish(),
            Self::KillSwitchDeactivateResult(r) => f
                .debug_tuple("KillSwitchDeactivateResult")
                .field(&r.as_ref().map(|_| ()).map_err(|e| e.as_str()))
                .finish(),
            Self::WindowCloseRequested(_) => f.write_str("WindowCloseRequested"),
            Self::Scanner(msg) => f.debug_tuple("Scanner").field(msg).finish(),
            Self::ScannerPoll => f.write_str("ScannerPoll"),
            Self::Tick => f.write_str("Tick"),
            Self::CertPinMismatchDismiss => f.write_str("CertPinMismatchDismiss"),
            Self::CertPinMismatchClearAndRetry => f.write_str("CertPinMismatchClearAndRetry"),
            Self::CertPinMismatchConfirmClear => f.write_str("CertPinMismatchConfirmClear"),
        }
    }
}
