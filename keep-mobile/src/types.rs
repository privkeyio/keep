// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignRequest {
    pub id: String,
    pub session_id: Vec<u8>,
    pub message_type: String,
    pub message_preview: String,
    pub from_peer: u16,
    pub timestamp: u64,
    pub metadata: Option<SignRequestMetadata>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignRequestMetadata {
    pub event_kind: Option<u32>,
    pub content_preview: Option<String>,
    pub amount_sats: Option<u64>,
    pub destination: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PeerInfo {
    pub share_index: u16,
    pub name: Option<String>,
    pub status: PeerStatus,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum PeerStatus {
    Online,
    Offline,
    Unknown,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ThresholdConfig {
    pub threshold: u16,
    pub total_shares: u16,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct GeneratedShareInfo {
    pub share_index: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: String,
    pub export_data: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct FrostGenerationResult {
    pub group_pubkey: String,
    pub shares: Vec<GeneratedShareInfo>,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum DkgStatus {
    NotStarted,
    Round1,
    Round2,
    Complete,
    Failed { reason: String },
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct DkgConfig {
    pub group_name: String,
    pub threshold: u16,
    pub participants: u16,
    pub our_index: u16,
    pub relays: Vec<String>,
}

#[derive(uniffi::Record, Clone)]
pub struct WalletDescriptorInfo {
    pub group_pubkey: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub created_at: u64,
}

impl std::fmt::Debug for WalletDescriptorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDescriptorInfo")
            .field("group_pubkey", &self.group_pubkey)
            .field("external_descriptor", &"[redacted]")
            .field("internal_descriptor", &"[redacted]")
            .field("network", &self.network)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct RecoveryTierConfig {
    pub threshold: u32,
    pub timelock_months: u32,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct DescriptorProposal {
    pub session_id: String,
    pub network: String,
    pub tiers: Vec<RecoveryTierConfig>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AnnouncedXpubInfo {
    pub xpub: String,
    pub fingerprint: String,
    pub label: Option<String>,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error { message: String },
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct KeepLiveState {
    pub rev: u64,
    pub connection_status: ConnectionStatus,
    pub peers: Vec<PeerInfo>,
    pub pending_requests: Vec<SignRequest>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct KeyHealthStatusInfo {
    pub group_pubkey: String,
    pub share_index: u16,
    pub last_check_timestamp: u64,
    pub responsive: bool,
    pub created_at: u64,
    pub is_stale: bool,
    pub is_critical: bool,
}
