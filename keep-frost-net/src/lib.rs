// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! FROST coordination protocol over nostr (KFP - Keep FROST Protocol).
//!
//! # Overview
//!
//! This crate implements distributed FROST threshold signing over nostr relays.
//! Participants discover each other, coordinate signing sessions, and exchange
//! cryptographic commitments and shares using encrypted nostr events.
//!
//! # Protocol Flow
//!
//! ```text
//! 1. ANNOUNCE     Peers broadcast presence for a group pubkey
//!                 ┌─────┐         ┌─────┐         ┌─────┐
//!                 │ P1  │◄───────►│Relay│◄───────►│ P2  │
//!                 └─────┘announce └─────┘announce └─────┘
//!
//! 2. SIGN_REQUEST Initiator requests signatures for a message
//!                 ┌─────┐sign_req ┌─────┐         ┌─────┐
//!                 │ P1  │────────►│Relay│────────►│ P2  │
//!                 └─────┘         └─────┘         └─────┘
//!
//! 3. COMMITMENT   Participants send FROST round 1 commitments
//!                 ┌─────┐         ┌─────┐commit   ┌─────┐
//!                 │ P1  │◄────────│Relay│◄────────│ P2  │
//!                 └─────┘         └─────┘         └─────┘
//!
//! 4. SIGNATURE    Participants send FROST round 2 signature shares
//!                 ┌─────┐         ┌─────┐share    ┌─────┐
//!                 │ P1  │◄────────│Relay│◄────────│ P2  │
//!                 └─────┘         └─────┘         └─────┘
//!
//! 5. COMPLETE     Initiator broadcasts aggregated signature
//!                 ┌─────┐complete ┌─────┐         ┌─────┐
//!                 │ P1  │────────►│Relay│────────►│ P2  │
//!                 └─────┘         └─────┘         └─────┘
//! ```
//!
//! # Message Types
//!
//! - `Announce`: Peer discovery, broadcasts share index and capabilities
//! - `SignRequest`: Initiates a signing session with message hash
//! - `Commitment`: FROST round 1 nonce commitments
//! - `SignatureShare`: FROST round 2 partial signatures
//! - `SignatureComplete`: Final aggregated BIP-340 signature
//! - `Ping/Pong`: Liveness checks
//! - `Error`: Session failure notifications
//!
//! # Security
//!
//! - All messages are NIP-44 encrypted between participants
//! - Session IDs prevent replay attacks
//! - Commitments are verified before generating signature shares

#![forbid(unsafe_code)]

mod attestation;
mod audit;
mod cert_pin;
mod descriptor_session;
mod descriptor_session_store;
mod ecdh;
mod error;
mod event;
mod node;
mod nonce_store;
mod peer;
pub mod proof;
mod protocol;
mod psbt_session;
mod session;

pub use attestation::{derive_attestation_nonce, verify_peer_attestation, ExpectedPcrs};
pub use audit::{SigningAuditEntry, SigningAuditLog, SigningOperation};
pub use cert_pin::{verify_relay_certificate, CertificatePinSet, SpkiHash};
pub use descriptor_session::{
    derive_descriptor_session_id, derive_policy_hash, participant_indices, reconstruct_descriptor,
    DescriptorSession, DescriptorSessionManager, DescriptorSessionState, DescriptorSessionStore,
    FinalizedDescriptor, PersistedDescriptorSession, PersistedFinalizedDescriptor,
    PersistedSessionState, XpubContribution,
};
pub use descriptor_session_store::FileDescriptorSessionStore;
pub use ecdh::{
    aggregate_ecdh_shares, compute_partial_ecdh, derive_ecdh_session_id, EcdhSession,
    EcdhSessionManager, EcdhSessionState,
};
pub use error::{FrostNetError, Result};
pub use event::KfpEventBuilder;
pub use node::{
    HealthCheckResult, KfpNode, KfpNodeEvent, NoOpHooks, PeerPolicy, SessionInfo, SigningHooks,
};
pub use nonce_store::{FileNonceStore, MemoryNonceStore, NonceStore};
pub use peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
pub use protocol::{
    AnnouncePayload, AnnouncedXpub, CommitmentPayload, DescriptorAckPayload,
    DescriptorContributePayload, DescriptorFinalizePayload, DescriptorNackPayload,
    DescriptorProposePayload, EcdhCompletePayload, EcdhRequestPayload, EcdhSharePayload,
    EnclaveAttestation, ErrorPayload, KeySlot, KfpMessage, PingPayload, PolicyTier, PongPayload,
    PsbtAbortPayload, PsbtFinalizePayload, PsbtInputInfo, PsbtOutputInfo, PsbtProposePayload,
    PsbtSignPayload, RefreshCompletePayload, RefreshRequestPayload, RefreshRound1Payload,
    RefreshRound2Payload, SignRequestPayload, SignatureCompletePayload, SignatureSharePayload,
    WalletPolicy, XpubAnnouncePayload, DEFAULT_REPLAY_WINDOW_SECS,
    DESCRIPTOR_ACK_PHASE_TIMEOUT_SECS, DESCRIPTOR_ACK_TIMEOUT_SECS,
    DESCRIPTOR_CONTRIBUTION_TIMEOUT_SECS, DESCRIPTOR_FINALIZE_TIMEOUT_SECS,
    DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS, DESCRIPTOR_SESSION_TIMEOUT_SECS, KFP_EVENT_KIND,
    KFP_VERSION, MAX_CAPABILITIES, MAX_CAPABILITY_LENGTH, MAX_COMMITMENT_SIZE,
    MAX_DESCRIPTOR_LENGTH, MAX_ERROR_CODE_LENGTH, MAX_ERROR_MESSAGE_LENGTH, MAX_FINGERPRINT_LENGTH,
    MAX_KEYS_PER_TIER, MAX_MESSAGE_SIZE, MAX_MESSAGE_TYPE_LENGTH, MAX_NACK_REASON_LENGTH,
    MAX_NAME_LENGTH, MAX_PARTICIPANTS, MAX_PSBT_ADDRESS_LENGTH, MAX_PSBT_INPUTS, MAX_PSBT_OUTPUTS,
    MAX_PSBT_SIZE, MAX_RECOVERY_TIERS, MAX_RECOVERY_XPUBS, MAX_SIGNATURE_SHARE_SIZE,
    MAX_XPUB_LABEL_LENGTH, MAX_XPUB_LENGTH, MIN_XPUB_LENGTH, PSBT_FINALIZE_PHASE_TIMEOUT_SECS,
    PSBT_SESSION_MAX_TIMEOUT_SECS, PSBT_SESSION_TIMEOUT_SECS, PSBT_SIGNING_PHASE_TIMEOUT_SECS,
    VALID_NETWORKS, VALID_XPUB_PREFIXES,
};
pub use psbt_session::{
    derive_psbt_session_id, PsbtSession, PsbtSessionManager, PsbtSessionState, SignerId,
};
pub use session::{derive_session_id, NetworkSession, SessionManager, SessionState};

pub fn install_default_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}
