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
    Waiting,
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
