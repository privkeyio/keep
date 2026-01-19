// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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
mod error;
mod event;
mod node;
mod nonce_store;
mod peer;
pub mod proof;
mod protocol;
mod session;

pub use attestation::{derive_attestation_nonce, verify_peer_attestation, ExpectedPcrs};
pub use audit::{SigningAuditEntry, SigningAuditLog, SigningOperation};
pub use error::{FrostNetError, Result};
pub use event::KfpEventBuilder;
pub use node::{KfpNode, KfpNodeEvent, NoOpHooks, PeerPolicy, SessionInfo, SigningHooks};
pub use nonce_store::{FileNonceStore, MemoryNonceStore, NonceStore};
pub use peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
pub use protocol::{
    AnnouncePayload, CommitmentPayload, EnclaveAttestation, ErrorPayload, KfpMessage, PingPayload,
    PongPayload, SignRequestPayload, SignatureCompletePayload, SignatureSharePayload,
    DEFAULT_REPLAY_WINDOW_SECS, KFP_EVENT_KIND, KFP_VERSION, MAX_CAPABILITIES,
    MAX_CAPABILITY_LENGTH, MAX_COMMITMENT_SIZE, MAX_ERROR_CODE_LENGTH, MAX_ERROR_MESSAGE_LENGTH,
    MAX_MESSAGE_SIZE, MAX_MESSAGE_TYPE_LENGTH, MAX_NAME_LENGTH, MAX_PARTICIPANTS,
    MAX_SIGNATURE_SHARE_SIZE,
};
pub use session::{derive_session_id, NetworkSession, SessionManager, SessionState};
