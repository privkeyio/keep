// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The seam between the announce path and a TPM quote producer.
//!
//! A node that holds its measured-boot attestation in a TPM produces a fresh
//! quote for every announce (each announce carries a fresh timestamp, and the
//! quote is bound to it). The producer links the tpm2-tss C stack and its
//! `tss-esapi` context is `!Send`, so it cannot live inside the spawned async
//! node; the concrete implementation (`TpmQuoteService`, feature
//! `tpm-attestation`) owns the producer on a dedicated thread and is reached
//! over a channel.
//!
//! This trait is the feature-agnostic, `dyn`-safe handle the node holds. The
//! async boundary is the returned [`oneshot::Receiver`] rather than an `async
//! fn`, so the trait stays object-safe without an `async-trait` dependency, and
//! it is trivially mockable in tests that do not have a TPM.

use tokio::sync::oneshot;

use crate::error::Result;
use crate::protocol::TpmQuoteEvidence;

/// Supplies a TPM quote bound to a specific announce.
pub trait AnnounceAttestor: Send + Sync {
    /// The 65-byte uncompressed SEC1 AK identity this attestor signs with. The
    /// verifier pins this out of band; exposed here for provisioning/diagnostics.
    fn ak_sec1(&self) -> Vec<u8>;

    /// Request a quote whose `qualifyingData` is `nonce` (the announce-bound
    /// value from [`crate::attestation::derive_announce_attestation_nonce`]).
    /// Returns immediately; await the receiver for the evidence. A dropped
    /// (cancelled) sender surfaces as a `RecvError` on the receiver.
    fn request_quote(&self, nonce: [u8; 32]) -> oneshot::Receiver<Result<TpmQuoteEvidence>>;
}
