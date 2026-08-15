// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignRequest {
    pub id: String,
    pub session_id: Vec<u8>,
    pub message_type: String,
    /// Whether [`Self::message_type`] was proven against the signed bytes rather
    /// than merely asserted by the requester.
    ///
    /// True when the request carried a structured body and the responder
    /// recomputed the digest that body produces and got the bytes being signed.
    /// A caller cannot relabel a Bitcoin sighash as a nostr event that way,
    /// because the canonical hash of the supplied event would not equal the
    /// sighash. False means nothing checked the label and it is a bare claim.
    ///
    /// Surfaces should say which one they are showing. A qualifier on every
    /// request, including the ones that are provable, teaches people to ignore
    /// it.
    pub type_verified: bool,
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

/// One entry of the invite-supplied DKG roster: a participant's 1-indexed
/// position and the hex (or npub) pubkey of its per-group signing subkey, as
/// printed by `frost_dkg_begin` on that device and collected out of band.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct DkgParticipant {
    pub index: u16,
    pub pubkey: String,
}

#[derive(uniffi::Record, Clone)]
pub struct DkgConfig {
    pub group_name: String,
    pub threshold: u16,
    pub participants: u16,
    pub our_index: u16,
    pub relays: Vec<String>,
    /// The invite-supplied roster: every participant's index and per-group
    /// subkey pubkey. This funnels through the same `frost_group_id`/roster
    /// verification the CLI uses (§4), so there is one authenticated identity
    /// path regardless of whether the roster was invite-supplied (mobile) or
    /// relay-fetched (CLI). The `d`-tag channel is the `frost_group_id` hex, so
    /// a mobile run and a CLI run of the same group interop on the wire.
    pub roster: Vec<DkgParticipant>,
}

/// Hand-written so a `toString()` across the UniFFI boundary cannot dump the
/// full roster; the ceremony parameters are shown, the participant keys summarized
/// by count (§8).
impl std::fmt::Debug for DkgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgConfig")
            .field("group_name", &self.group_name)
            .field("threshold", &self.threshold)
            .field("participants", &self.participants)
            .field("our_index", &self.our_index)
            .field("relays", &self.relays)
            .field("roster", &format_args!("[{} participants]", self.roster.len()))
            .finish()
    }
}

/// Progress of a relay-driven DKG run, surfaced to the native layer so it can
/// render setup state. Terminal states are `Complete` and `Failed`; errors do
/// not cross the FFI as exceptions during the run, they arrive here.
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum DkgProgressUpdate {
    /// Establishing the relay connection with the bootstrap identity.
    Connecting,
    /// Waiting on peers' round-1 packages. `received` counts distinct peers so
    /// far (excluding us); `total` is the number of peers expected.
    Round1 { received: u16, total: u16 },
    /// Waiting on the round-2 packages addressed to this device.
    Round2 { received: u16, total: u16 },
    /// All packages in; running the final key derivation.
    Finalizing,
    /// Broadcasting/collecting the transcript confirmation (CertEq, §6).
    /// `confirmed` counts distinct peers that signed the identical transcript.
    Confirming { confirmed: u16, total: u16 },
    /// DKG succeeded, the CertEq certificate is complete, and the share is
    /// stored. Never fired before the certificate is in hand (§6/§8).
    Complete { group_pubkey: String },
    /// DKG aborted. `reason` is human-readable and safe to display.
    Failed { reason: String },
}

#[derive(uniffi::Record, Clone)]
pub struct WalletDescriptorInfo {
    pub group_pubkey: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub created_at: u64,
    pub device_registrations: Vec<DeviceRegistrationInfo>,
    pub policy_hash_hex: Option<String>,
    /// Monotonic version of this descriptor for the group. `1` for the
    /// initial descriptor; increments on each migration.
    pub version: u32,
    /// Hex-encoded 32-byte canonical hash of the descriptor this one
    /// supersedes, when this is a migration. `None` for the initial
    /// descriptor or for legacy records persisted before versioning.
    pub previous_descriptor_hash_hex: Option<String>,
    pub policy_json: Option<String>,
}

impl std::fmt::Debug for WalletDescriptorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDescriptorInfo")
            .field("group_pubkey", &self.group_pubkey)
            .field("external_descriptor", &"[redacted]")
            .field("internal_descriptor", &"[redacted]")
            .field("network", &self.network)
            .field("created_at", &self.created_at)
            .field("device_registrations", &self.device_registrations.len())
            .field("policy_hash_hex", &self.policy_hash_hex)
            .field("version", &self.version)
            .field(
                "previous_descriptor_hash_hex",
                &self.previous_descriptor_hash_hex,
            )
            .finish()
    }
}

#[derive(uniffi::Record, Clone)]
pub struct DeviceRegistrationInfo {
    pub signer_pubkey: String,
    pub wallet_name: String,
    pub hmac: Option<String>,
    pub registered_at: u64,
    pub device_kind: Option<String>,
    pub fingerprint_hex: Option<String>,
    pub firmware_version: Option<String>,
}

impl std::fmt::Debug for DeviceRegistrationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistrationInfo")
            .field("signer_pubkey", &self.signer_pubkey)
            .field("wallet_name", &self.wallet_name)
            .field("hmac", &self.hmac.as_ref().map(|_| "<redacted>"))
            .field("registered_at", &self.registered_at)
            .field("device_kind", &self.device_kind)
            .field("fingerprint_hex", &self.fingerprint_hex)
            .field("firmware_version", &self.firmware_version)
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
pub struct BackupInfo {
    pub key_count: u32,
    pub share_count: u32,
    pub descriptor_count: u32,
    pub created_at: String,
    pub file_size: u64,
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
