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

mod announce_attestor;
mod attestation;
mod audit;
mod cert_pin;
mod descriptor_session;
mod descriptor_session_store;
mod ecdh;
mod enroll_session;
mod error;
mod event;
mod node;
mod nonce_pool;
mod nonce_store;
mod oprf_session;
mod peer;
mod pinning;
pub mod proof;
mod protocol;
mod psbt_session;
mod recovery_signers;
mod session;
mod state_event;
mod structured_payload;
#[cfg(any(test, feature = "testing"))]
pub mod test_support;
mod tpm_policy;
#[cfg(feature = "tpm-attestation")]
pub mod tpm_producer;
pub mod tpm_quote;

pub use announce_attestor::AnnounceAttestor;
pub use attestation::{
    derive_announce_attestation_nonce, derive_attestation_nonce, verify_peer_attestation,
    ExpectedPcrs,
};
pub use audit::{SigningAuditEntry, SigningAuditLog, SigningOperation};
pub use cert_pin::{verify_relay_certificate, CertificatePinSet, SpkiHash};
pub use descriptor_session::{
    derive_descriptor_session_id, derive_policy_hash, find_local_external_xpub_in_tier,
    load_verified_wallet_policy, participant_indices, reconstruct_descriptor, DescriptorSession,
    DescriptorSessionManager, DescriptorSessionState, DescriptorSessionStore, FinalizedDescriptor,
    PersistedDescriptorSession, PersistedFinalizedDescriptor, PersistedSessionState,
    XpubContribution,
};
pub use descriptor_session_store::FileDescriptorSessionStore;
pub use ecdh::{
    aggregate_ecdh_shares, compute_partial_ecdh, derive_ecdh_session_id, EcdhSession,
    EcdhSessionManager, EcdhSessionState,
};
pub use enroll_session::{
    derive_oprf_enroll_session_id, OprfEnrollSession, OprfEnrollSessionManager,
    OprfEnrollSessionState,
};
pub use error::{FrostNetError, Result};
pub use event::{verify_unwrapped_duress_beacon, KfpEventBuilder};
pub use node::{
    DescriptorLookupUnavailable, DuressFreeze, DuressPersister, HealthCheckResult,
    KeepDescriptorLookup, KfpNode, KfpNodeEvent, NoOpHooks, OprfShareSealAck, PeerPolicy,
    PersistedDescriptorLookup, PsbtSessionSnapshot, RefuseRawAndRequireStructuredHooks,
    RefuseRawSignatureHooks, RequireStructuredPayloadHooks, ServeHooks, SessionInfo, SigningHooks,
    SuccessorLookup,
};
pub use nonce_pool::{NonceId, NoncePool, DEFAULT_POOL_TARGET, MAX_POOL_ENTRIES};
pub use nonce_store::{FileNonceStore, MemoryNonceStore, NonceStore};
pub use oprf_session::{
    derive_oprf_session_id, OprfEvalRateLimiter, OprfUnlockSession, OprfUnlockSessionManager,
    OprfUnlockSessionState, MAX_OPRF_EVALS_PER_WINDOW, OPRF_EVAL_WINDOW,
};
pub use peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
pub use pinning::{OnNewPin, PinningServerCertVerifier};
pub use protocol::{
    AnnouncePayload, AnnouncedXpub, CommitmentPayload, DescriptorAckPayload,
    DescriptorContributePayload, DescriptorFinalizePayload, DescriptorNackPayload,
    DescriptorProposePayload, DuressBeaconPayload, EcdhCompletePayload, EcdhRequestPayload,
    EcdhSharePayload, EnclaveAttestation, ErrorPayload, KeySlot, KfpMessage,
    NonceCommitmentPayload, NonceRef, OprfEnrollAckPayload, OprfEnrollPayload,
    OprfEvalRequestPayload, OprfEvalSharePayload, PingPayload, PolicyTier, PongPayload,
    PreExchangedCommitment, PsbtAbortPayload, PsbtFinalizePayload, PsbtInputInfo, PsbtOutputInfo,
    PsbtProposePayload, PsbtSignPayload, RefreshCompletePayload, RefreshRequestPayload,
    RefreshRound1Payload, RefreshRound2Payload, SignRequestPayload, SignatureCompletePayload,
    SignatureSharePayload, TpmQuoteEvidence, WalletPolicy, XpubAnnouncePayload,
    DEFAULT_REPLAY_WINDOW_SECS, DESCRIPTOR_ACK_PHASE_TIMEOUT_SECS, DESCRIPTOR_ACK_TIMEOUT_SECS,
    DESCRIPTOR_CONTRIBUTION_TIMEOUT_SECS, DESCRIPTOR_FINALIZE_TIMEOUT_SECS,
    DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS, DESCRIPTOR_SESSION_TIMEOUT_SECS, KFP_EVENT_KIND,
    KFP_VERSION, MAX_CAPABILITIES, MAX_CAPABILITY_LENGTH, MAX_COMMITMENT_SIZE,
    MAX_DESCRIPTOR_LENGTH, MAX_ERROR_CODE_LENGTH, MAX_ERROR_MESSAGE_LENGTH, MAX_FINGERPRINT_LENGTH,
    MAX_KEYS_PER_TIER, MAX_MESSAGE_SIZE, MAX_MESSAGE_TYPE_LENGTH, MAX_NACK_REASON_LENGTH,
    MAX_NAME_LENGTH, MAX_NONCE_COMMITMENTS, MAX_PARTICIPANTS, MAX_PSBT_ADDRESS_LENGTH,
    MAX_PSBT_INPUTS, MAX_PSBT_OUTPUTS, MAX_PSBT_SIZE, MAX_RECOVERY_TIERS, MAX_RECOVERY_XPUBS,
    MAX_SIGNATURE_SHARE_SIZE, MAX_STRUCTURED_PAYLOAD_SIZE, MAX_XPUB_LABEL_LENGTH, MAX_XPUB_LENGTH,
    MIN_XPUB_LENGTH, MSG_TYPE_BITCOIN_SIGHASH, MSG_TYPE_NOSTR_EVENT, MSG_TYPE_RAW,
    OPRF_PARTIAL_LEN, PSBT_FINALIZE_PHASE_TIMEOUT_SECS, PSBT_SESSION_MAX_TIMEOUT_SECS,
    PSBT_SESSION_TIMEOUT_SECS, PSBT_SIGNING_PHASE_TIMEOUT_SECS, VALID_NETWORKS,
    VALID_XPUB_PREFIXES,
};
pub use psbt_session::{
    derive_psbt_session_id, PsbtSession, PsbtSessionManager, PsbtSessionState, SignerId,
};
pub use recovery_signers::{
    InMemoryRecoverySignerRegistry, RecoverySignerHandle, RecoverySignerRegistry,
};
pub use session::{
    derive_session_id, derive_session_id_salted, NetworkSession, SessionManager, SessionState,
};
pub use state_event::{
    parse_state_event, state_record_event, state_tombstone_event, StateRecord, KEEP_STATE_KIND,
    STATE_TABLES,
};
pub use structured_payload::{verify_structured_payload, BitcoinSighashPayload, NostrEventPayload};
pub use tpm_policy::TpmAttestationPolicy;
#[cfg(feature = "tpm-attestation")]
pub use tpm_producer::{TpmQuoteService, TpmQuoter, DEFAULT_PCR_SLOTS};

pub fn install_default_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}
