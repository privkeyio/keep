// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
mod descriptor;
mod ecdh;
mod enroll;
mod oprf;
mod psbt;
mod signing;

pub use psbt::PsbtSessionSnapshot;
pub(crate) use signing::SIGNING_ROUND_TIMEOUT;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rand::seq::IndexedRandom;
use nostr_sdk::prelude::*;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use keep_core::frost::SharePackage;
use keep_core::relay::{
    validate_relay_url, validate_relay_url_allow_internal, ALLOW_INTERNAL_HOSTS,
};

use crate::announce_attestor::AnnounceAttestor;
use crate::attestation::{
    derive_announce_attestation_nonce, verify_peer_attestation, ExpectedPcrs,
};
use crate::audit::SigningAuditLog;
use crate::descriptor_session::DescriptorSessionManager;
use crate::ecdh::EcdhSessionManager;
use crate::enroll_session::OprfEnrollSessionManager;
use crate::error::{FrostNetError, Result};
use crate::event::KfpEventBuilder;
use crate::nonce_pool::{NonceId, NoncePool};
use crate::nonce_store::{FileNonceStore, NonceStore};
use crate::oprf_session::{OprfEvalRateLimiter, OprfUnlockSessionManager};
use crate::peer::{AttestationStatus, Peer, PeerManager, PeerStatus};
use crate::protocol::*;
use crate::psbt_session::PsbtSessionManager;
use crate::session::{NetworkSession, SessionManager};
use crate::tpm_policy::{appraise_tpm_quote, TpmAttestationPolicy};

/// Error returned by [`PersistedDescriptorLookup::latest_version_for`] when
/// the underlying descriptor store cannot be queried (e.g. vault locked or
/// mutex poisoned). Callers must fail-closed rather than treating this as
/// "no descriptor known".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorLookupUnavailable;

impl std::fmt::Display for DescriptorLookupUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("persisted descriptor store unavailable")
    }
}

impl std::error::Error for DescriptorLookupUnavailable {}

/// Outcome of resolving the successor (NEW) descriptor for a session keyed on
/// an OLD descriptor hash. Used by responders to decide whether an automated
/// migration sweep destination must be re-derived and validated (#414).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorLookup {
    /// The session descriptor is the current tip: no descriptor back-points to
    /// it, so there is nothing to validate and signing may proceed.
    Tip,
    /// Exactly one successor descriptor was resolved. Carries its external
    /// (receive) descriptor and canonical network string so the destination can
    /// be re-derived against the *successor's own* network.
    Found {
        external_descriptor: String,
        network: String,
    },
    /// The descriptor store could not be read (vault locked or poisoned).
    /// Callers must fail closed rather than skip the destination check.
    Unavailable,
    /// More than one descriptor back-points to the session hash. The lineage is
    /// ambiguous and a destination cannot be derived deterministically; callers
    /// must fail closed.
    Ambiguous,
}

/// Fallback lookup for finalized wallet descriptors that have been persisted
/// outside of the in-memory `DescriptorSessionManager` (e.g. stored by the
/// host application). Used when a PSBT coordination message arrives for a
/// descriptor whose session is no longer held in memory (e.g. after restart).
pub trait PersistedDescriptorLookup: Send + Sync {
    /// Returns `true` if a persisted descriptor for `group` exists with the
    /// canonical hash equal to `hash`. Implementations must use the same
    /// length-framed digest produced by `WalletDescriptor::canonical_hash`,
    /// i.e. `sha256(le_u64(len(external)) || external || le_u64(len(internal))
    /// || internal || policy_hash)`, so the framed digests match across
    /// stores.
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool;

    /// Return the canonical network string of the persisted descriptor whose
    /// group + canonical hash match, if any. Used by snapshot helpers to
    /// report the network without having to infer it from output scripts
    /// (which mis-classifies regtest/testnet equivalences).
    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        let _ = (group, hash);
        None
    }

    /// Return the external (receive) descriptor string of the persisted
    /// descriptor whose group + canonical hash match, if any. Used by the
    /// migration sweep to bind a supplied recovery output to the persisted OLD
    /// descriptor, so the source of truth survives session reaping/restart.
    fn external_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        let _ = (group, hash);
        None
    }

    /// Return the largest persisted descriptor version for the given group,
    /// `Ok(None)` if no descriptor exists, or `Err(DescriptorLookupUnavailable)`
    /// if the underlying store could not be queried (e.g. vault locked). Used
    /// to validate that an inbound `DescriptorMigrate` strictly increases the
    /// version. No default impl is provided: silently returning `Ok(None)`
    /// would disable the monotonic version check, allowing downgrade replay
    /// of `DescriptorMigrate`. Callers must fail-closed on `Err(_)` rather
    /// than treating it as "no descriptor known".
    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, DescriptorLookupUnavailable>;

    /// Resolve the successor (NEW) descriptor for `group` whose
    /// `previous_descriptor_hash` equals `hash`.
    ///
    /// Used by responders to validate that a PSBT signature request keyed on an
    /// OLD descriptor (i.e. an automated migration sweep) actually pays a
    /// NEW-descriptor-controlled address. Without this check, an authorized
    /// proposer can drive any destination through `request_psbt_spend` (see
    /// #414) because the proposer-side re-derivation in
    /// `request_descriptor_migration_sweep` is not a security boundary.
    ///
    /// Implementations must fail closed: return [`SuccessorLookup::Unavailable`]
    /// when the store cannot be read and [`SuccessorLookup::Ambiguous`] when
    /// more than one descriptor back-points to `hash`. The default impl reports
    /// `Unavailable` so an unconfigured lookup never silently skips the check.
    fn successor_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> SuccessorLookup {
        let _ = (group, hash);
        SuccessorLookup::Unavailable
    }
}

/// Shared `PersistedDescriptorLookup` adapter over a `Keep` accessor closure.
///
/// The closure is invoked on every query and is expected to return the
/// currently-persisted descriptors, or `None` if the vault cannot be read
/// (e.g. locked or mutex poisoned). When the closure returns `None` the
/// lookup logs a warning and reports no match (fail-closed); callers must
/// ensure the vault is unlocked for PSBT coordination to succeed.
pub struct KeepDescriptorLookup<F>
where
    F: Fn() -> Option<Vec<keep_core::wallet::WalletDescriptor>> + Send + Sync + 'static,
{
    fetch: F,
}

impl<F> KeepDescriptorLookup<F>
where
    F: Fn() -> Option<Vec<keep_core::wallet::WalletDescriptor>> + Send + Sync + 'static,
{
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }

    fn lookup<T>(
        &self,
        f: impl FnOnce(&keep_core::wallet::WalletDescriptor) -> Option<T>,
        group: &[u8; 32],
        hash: &[u8; 32],
    ) -> Option<T> {
        let Some(descriptors) = (self.fetch)() else {
            tracing::warn!(
                group = %hex::encode(group),
                descriptor_hash = %hex::encode(hash),
                "KeepDescriptorLookup could not read persisted descriptors (vault locked or unavailable); treating as no-match",
            );
            return None;
        };
        descriptors
            .iter()
            .find(|d| &d.group_pubkey == group && &d.canonical_hash() == hash)
            .and_then(f)
    }
}

impl<F> PersistedDescriptorLookup for KeepDescriptorLookup<F>
where
    F: Fn() -> Option<Vec<keep_core::wallet::WalletDescriptor>> + Send + Sync + 'static,
{
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
        self.lookup(|_| Some(()), group, hash).is_some()
    }

    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        self.lookup(|d| Some(d.network.clone()), group, hash)
    }

    fn external_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        self.lookup(|d| Some(d.external_descriptor.clone()), group, hash)
    }

    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, DescriptorLookupUnavailable> {
        let Some(descriptors) = (self.fetch)() else {
            tracing::warn!(
                group = %hex::encode(group),
                "KeepDescriptorLookup could not read persisted descriptors for latest_version_for (vault locked or unavailable); failing closed",
            );
            return Err(DescriptorLookupUnavailable);
        };
        Ok(descriptors
            .iter()
            .filter(|d| &d.group_pubkey == group)
            .map(|d| d.version)
            .max())
    }

    fn successor_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> SuccessorLookup {
        let Some(descriptors) = (self.fetch)() else {
            tracing::warn!(
                group = %hex::encode(group),
                descriptor_hash = %hex::encode(hash),
                "KeepDescriptorLookup could not read persisted descriptors for successor_for (vault locked or unavailable); failing closed",
            );
            return SuccessorLookup::Unavailable;
        };
        // Resolve the session descriptor's own version from the same snapshot so
        // the read is a single lock-scope (no TOCTOU vs. the caller's separate
        // OLD-descriptor fetch) and so an n+1 successor can be selected
        // deterministically.
        let session_version = descriptors
            .iter()
            .find(|d| &d.group_pubkey == group && &d.canonical_hash() == hash)
            .map(|d| d.version);
        let is_successor = |d: &&keep_core::wallet::WalletDescriptor| {
            &d.group_pubkey == group && d.previous_descriptor_hash.as_ref() == Some(hash)
        };
        let matches: Vec<&keep_core::wallet::WalletDescriptor> =
            descriptors.iter().filter(is_successor).collect();
        match matches.as_slice() {
            [] => SuccessorLookup::Tip,
            [only] => SuccessorLookup::Found {
                external_descriptor: only.external_descriptor.clone(),
                network: only.network.clone(),
            },
            _ => {
                // If multiple descriptors back-point to the same OLD hash, prefer
                // the one at version session+1; only fail closed when the lineage
                // is genuinely ambiguous (no single n+1 successor).
                let next_version = session_version.map(|v| v.saturating_add(1));
                let chosen: Vec<&keep_core::wallet::WalletDescriptor> = match next_version {
                    Some(nv) => matches
                        .iter()
                        .copied()
                        .filter(|d| d.version == nv)
                        .collect(),
                    None => Vec::new(),
                };
                if let [only] = chosen.as_slice() {
                    return SuccessorLookup::Found {
                        external_descriptor: only.external_descriptor.clone(),
                        network: only.network.clone(),
                    };
                }
                tracing::warn!(
                    group = %hex::encode(group),
                    descriptor_hash = %hex::encode(hash),
                    successor_count = matches.len(),
                    "multiple descriptors back-point to the session hash with no single version+1 successor; failing closed (ambiguous lineage)",
                );
                SuccessorLookup::Ambiguous
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerPolicy {
    pub pubkey: PublicKey,
    pub allow_send: bool,
    pub allow_receive: bool,
}

impl PeerPolicy {
    pub fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            allow_send: true,
            allow_receive: true,
        }
    }

    pub fn allow_send(mut self, allow: bool) -> Self {
        self.allow_send = allow;
        self
    }

    pub fn allow_receive(mut self, allow: bool) -> Self {
        self.allow_receive = allow;
        self
    }
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub session_id: [u8; 32],
    pub message: Vec<u8>,
    pub threshold: u16,
    pub participants: Vec<u16>,
    pub requester: u16,
    /// Requester-supplied label for the 32 bytes in `message`. Frost-secp256k1
    /// signs the bytes verbatim, so a "nostr-event" digest is byte-for-byte
    /// indistinguishable from a Bitcoin taproot key-path sighash. Hooks use
    /// this to gate (or refuse) requests whose label doesn't match the
    /// expected domain on this group. See [`RefuseRawSignatureHooks`].
    pub message_type: String,
    /// Optional structured payload the requester attached so the responder
    /// can recompute the digest from a typed body and reject cross-domain
    /// label spoofs (#529). Presence is required by
    /// [`RequireStructuredPayloadHooks`] for hybrid Nostr + Bitcoin groups;
    /// the recompute-and-compare is performed unconditionally when present.
    pub structured_payload: Option<Vec<u8>>,
}

impl From<&NetworkSession> for SessionInfo {
    fn from(session: &NetworkSession) -> Self {
        Self {
            session_id: *session.session_id(),
            message: session.message().to_vec(),
            threshold: session.threshold(),
            participants: session.participants().to_vec(),
            // NetworkSession does not retain the requester index, so this
            // post_sign-side conversion cannot populate it; message_type is
            // carried through so post_sign sees the original domain label.
            requester: 0,
            message_type: session.message_type().to_string(),
            // NetworkSession does not persist the structured payload (only the
            // digest is signed); post_sign observers see the domain label but
            // not the body. Fine for notification purposes; the recompute
            // check runs in pre_sign where the request is in scope.
            structured_payload: None,
        }
    }
}

/// Hooks for observing and controlling the signing process.
///
/// Implementations should be non-blocking and return quickly to avoid
/// delaying the signing protocol. To prevent deadlocks, hook implementations
/// must not call `KfpNode::set_hooks` from within a hook.
pub trait SigningHooks: Send + Sync {
    /// Called before a node participates in a signing session.
    ///
    /// Returning an `Err` will abort the signing session.
    fn pre_sign(&self, session: &SessionInfo) -> Result<()>;

    /// Called after a signature has been successfully generated.
    ///
    /// This is for notification purposes and cannot fail. Long-running
    /// operations should be offloaded to a separate task.
    fn post_sign(&self, session: &SessionInfo, signature: &[u8; 64]);

    /// Called by an OPRF-unlock holder before it evaluates a requester's blinded
    /// element. Returning `false` declines the evaluation without producing a
    /// partial.
    ///
    /// SECURITY: the default is DENY. The OPRF input is a fixed, low-entropy
    /// label and the box already holds one share, so in a 2-of-3 a single
    /// auto-answered evaluation is enough to derive the volume key (the rate
    /// limit does not help: one eval suffices). A holder MUST therefore opt in
    /// explicitly by overriding this with a real policy (human approval on the
    /// phone, an out-of-band confirmation on the replica). Leaving the default
    /// keeps the oracle closed.
    ///
    /// Returns a boxed future rather than using `async fn` so the trait stays
    /// object-safe (`Arc<dyn SigningHooks>`), avoiding an `async-trait`
    /// dependency for one method.
    fn approve_oprf_eval(
        &self,
        requester_share_index: u16,
        session_id: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let _ = (requester_share_index, session_id);
        Box::pin(async { false })
    }
}

pub struct NoOpHooks;

impl SigningHooks for NoOpHooks {
    fn pre_sign(&self, _session: &SessionInfo) -> Result<()> {
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Pre-sign policy that refuses requests whose `message_type` label is `"raw"`
/// (compared case- and whitespace-insensitively).
///
/// The honest signing paths that produce unstructured 32-byte digests, the
/// built-in `frost-network sign` command and the hardware bridge, label them
/// `"raw"`. A signature over such a digest is byte-for-byte indistinguishable
/// from a Bitcoin taproot key-path sighash for the same group key, so on a
/// group that also coordinates a Bitcoin wallet descriptor a `"raw"` request
/// can be confused with (or substituted for) a spend authorization. Operators
/// of hybrid Nostr + Bitcoin groups install this hook so those raw requests
/// are rejected and only structured, domain-labeled requests proceed.
///
/// This is a denylist, not an allowlist: it stops the honest raw-signing
/// paths, but it does NOT stop an adversary. Because `message_type` is
/// requester-supplied and not bound to the signed bytes, a caller can relabel
/// a sighash as `"nostr-event"` (or anything else) and bypass the gate. The
/// real fix, binding the domain into the signed digest on the responder side,
/// is tracked under #524; until then, refusing `"raw"` outright is the
/// cheapest correctness-preserving gate against accidental misuse.
pub struct RefuseRawSignatureHooks;

impl SigningHooks for RefuseRawSignatureHooks {
    fn pre_sign(&self, session: &SessionInfo) -> Result<()> {
        if session
            .message_type
            .trim()
            .eq_ignore_ascii_case(crate::MSG_TYPE_RAW)
        {
            return Err(FrostNetError::PolicyViolation(format!(
                "co-signer refuses message_type=\"raw\" (group coordinates structured signatures only; see #524). \
                 session_id={}, requester=share {}",
                hex::encode(session.session_id),
                session.requester
            )));
        }
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Pre-sign policy that refuses any request without a structured payload
/// (#529). Complement to [`RefuseRawSignatureHooks`]: raw is refused by
/// label, everything else must attach a typed body the responder recomputes
/// against. Combining the two closes the label-spoof hole for hybrid groups
/// that coordinate both Nostr events and Bitcoin taproot key-spend sighashes:
/// a caller can no longer relabel a Bitcoin sighash as `"nostr-event"` to
/// bypass the raw denylist, because the responder rejects a nostr-event that
/// carries no structured payload before the signing round begins, and
/// rejects one whose recomputed digest does not match `message`.
///
/// Default is OFF: existing groups keep working after a partial upgrade.
/// Operators flip this on per-group once all participants understand
/// structured payloads (see the migration story in #529).
pub struct RequireStructuredPayloadHooks;

impl SigningHooks for RequireStructuredPayloadHooks {
    fn pre_sign(&self, session: &SessionInfo) -> Result<()> {
        if session.structured_payload.is_none() {
            return Err(FrostNetError::PolicyViolation(format!(
                "co-signer requires a structured payload for every sign request (#529). \
                 session_id={}, requester=share {}, message_type={:?}",
                hex::encode(session.session_id),
                session.requester,
                session.message_type
            )));
        }
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Combined pre-sign policy for hybrid Nostr + Bitcoin groups (#529): refuses
/// unstructured `"raw"` requests AND requires a structured payload on every
/// other request so the label always maps to a recomputable body. This is
/// the recommended production policy once all group participants understand
/// structured payloads; the two hooks compose but bundling them here saves
/// operators from wiring both by hand.
pub struct RefuseRawAndRequireStructuredHooks;

impl SigningHooks for RefuseRawAndRequireStructuredHooks {
    fn pre_sign(&self, session: &SessionInfo) -> Result<()> {
        RefuseRawSignatureHooks.pre_sign(session)?;
        RequireStructuredPayloadHooks.pre_sign(session)?;
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Hooks for `frost network serve`: optionally refuse `message_type="raw"`
/// signing requests (see [`RefuseRawSignatureHooks`]), and optionally
/// auto-approve OPRF evaluation requests.
///
/// Auto-approving the OPRF oracle is the explicit operator policy the default-DENY
/// `approve_oprf_eval` requires. The real and ONLY security boundary for auto-approve
/// is VERIFIED TPM attestation of the requester (AK pinning plus PCR correctness;
/// `NotConfigured` is rejected, so the oracle fails closed) combined with this explicit
/// opt-in. Safety rests on WHO is answered, not on how many evals occur. The
/// per-requester rate limiter is NOT a meaningful barrier against a determined attacker:
/// the requester transport pubkey it keys on is derived deterministically from the
/// public `(group_pubkey, identifier)`, so an attacker who knows the public group key can
/// rotate member identities to sidestep both the rate limiter and the share-index gate.
/// The rate limiter is best-effort abuse control against accidental or naive
/// over-querying only. This flag lets an autonomous holder (e.g. a replica) answer
/// verified requests unattended; leave it off for a holder that gates each evaluation
/// behind a human (e.g. a phone).
pub struct ServeHooks {
    pub refuse_raw_sign: bool,
    pub require_structured_payload: bool,
    pub auto_approve_oprf_eval: bool,
}

impl SigningHooks for ServeHooks {
    fn pre_sign(&self, session: &SessionInfo) -> Result<()> {
        // Delegate to the shared raw-sign policy so the predicate and message stay
        // centralized rather than duplicated here.
        if self.refuse_raw_sign {
            RefuseRawSignatureHooks.pre_sign(session)?;
        }
        if self.require_structured_payload {
            RequireStructuredPayloadHooks.pre_sign(session)?;
        }
        Ok(())
    }
    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
    fn approve_oprf_eval(
        &self,
        _requester_share_index: u16,
        _session_id: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let approve = self.auto_approve_oprf_eval;
        Box::pin(async move { approve })
    }
}

#[derive(Clone, Debug)]
pub struct HealthCheckResult {
    pub responsive: Vec<u16>,
    pub unresponsive: Vec<u16>,
}

/// Maximum age for announcement timestamps (5 minutes)
pub(crate) const ANNOUNCE_MAX_AGE_SECS: u64 = 300;
/// Maximum clock skew tolerance for future timestamps (30 seconds)
pub(crate) const ANNOUNCE_MAX_FUTURE_SECS: u64 = 30;
/// Maximum time to wait for a TPM quote during announce before failing closed.
/// The TPM `quote()` is a blocking hardware call; bounding it keeps a wedged or
/// slow TPM from stalling the inbound message-processing loop.
const ANNOUNCE_QUOTE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the early-exit liveness ping re-checks for pongs while waiting.
const LIVENESS_PING_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Upper bound on how long a holder blocks the inbound-message loop waiting for a subscriber to
/// confirm it durably sealed an OPRF enrollment share. Kept well under the default session timeout
/// so the loop is not deaf for a full session and the resulting ack still reaches the dealer inside
/// its own ack-wait. A real TPM/keystore seal completes in well under this; the bound exists to
/// catch a subscriber that never seals.
pub(crate) const OPRF_SEAL_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);

/// Durable-custody ack-back channel for [`KfpNodeEvent::OprfShareReceived`]. The
/// subscriber that durably seals the share takes the sender and reports the seal
/// result; the holder acks the dealer only on a confirmed `true`. Wrapped in
/// `Arc<Mutex<Option<_>>>` so the broadcast event remains `Clone` while the
/// single-shot sender can be taken by exactly one subscriber.
pub type OprfShareSealAck = Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>;

#[derive(Clone)]
pub enum KfpNodeEvent {
    PeerDiscovered {
        share_index: u16,
        name: Option<String>,
    },
    PeerOffline {
        share_index: u16,
    },
    SigningStarted {
        session_id: [u8; 32],
    },
    SignatureComplete {
        session_id: [u8; 32],
        signature: [u8; 64],
    },
    SigningFailed {
        session_id: [u8; 32],
        error: String,
        /// Peer-reported error code (e.g. `stale_nonce`), used by the requester
        /// to decide whether the failure is recoverable in place or whether the
        /// offending peer should be excluded and the round failed over.
        code: String,
        /// Share index of the peer that reported the error, when resolvable.
        /// Carried structurally so failover can exclude exactly that peer
        /// without parsing it back out of the human-readable `error` string.
        offending_index: Option<u16>,
    },
    EcdhComplete {
        session_id: [u8; 32],
        shared_secret: Zeroizing<[u8; 32]>,
    },
    EcdhFailed {
        session_id: [u8; 32],
        error: String,
    },
    /// A holder received and accepted an OPRF evaluation request (emitted around
    /// the approval hook, before the partial is produced).
    OprfEvalRequested {
        session_id: [u8; 32],
        requester_index: u16,
    },
    /// The box collected a quorum of partials and derived the LUKS key locally.
    ///
    /// SECURITY: this carries the derived key on the shared broadcast bus, so any
    /// `subscribe()`er in-process sees it (the `Debug` impl redacts it, and it is
    /// never serialized to the wire). This mirrors `EcdhComplete`; prefer the
    /// `request_oprf_unlock` return value and do not log the event payload. See
    /// the follow-up to move both off the broadcast bus to a per-session channel.
    OprfUnlockComplete {
        session_id: [u8; 32],
        luks_key: Zeroizing<[u8; 32]>,
    },
    OprfUnlockFailed {
        session_id: [u8; 32],
        error: String,
    },
    /// A holder took custody of a validated OPRF secret key share from a trusted
    /// dealer. The node/app must seal `share` (TPM or keystore).
    ///
    /// SECURITY: this carries live key material on the shared broadcast bus; the
    /// `Debug` impl redacts it and it is never serialized to the wire. Prefer
    /// sealing it immediately and do not log the event payload.
    OprfShareReceived {
        dealer_index: u16,
        threshold: u16,
        total: u16,
        share: Zeroizing<Vec<u8>>,
        /// Durable-custody ack-back. The consumer that seals `share` MUST take the
        /// sender (`lock().take()`) and send `true` on a confirmed seal or `false`
        /// on failure. The holder withholds its enrollment ack to the dealer until
        /// it observes `true`: if every subscriber ignores the event the sender is
        /// dropped and the receiver resolves `Err`, so custody is reported failed
        /// rather than the dealer being told enrollment completed with nothing
        /// sealed. Wrapped so the broadcast event stays `Clone`; only one
        /// subscriber can take the single-shot sender.
        seal_ack: OprfShareSealAck,
    },
    /// The dealer collected an ack from every enrollment target.
    OprfEnrollComplete {
        session_id: [u8; 32],
    },
    OprfEnrollFailed {
        session_id: [u8; 32],
        error: String,
    },
    DescriptorProposed {
        session_id: [u8; 32],
    },
    DescriptorContributionNeeded {
        session_id: [u8; 32],
        policy: WalletPolicy,
        network: String,
        initiator_pubkey: PublicKey,
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
        network: String,
        policy_hash: [u8; 32],
        /// Monotonic version of the finalized descriptor (from the session
        /// policy). The persistence layer must record this rather than
        /// hard-coding [`keep_core::wallet::INITIAL_DESCRIPTOR_VERSION`] so
        /// migration lineage is preserved when this completion was a v2+
        /// descriptor.
        version: u32,
        policy: WalletPolicy,
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
    /// A peer announced a descriptor-migration link (old → new).
    /// Receivers should persist `previous_descriptor_hash` on the matching
    /// new descriptor record.
    DescriptorMigrateReceived {
        session_id: [u8; 32],
        group_pubkey: [u8; 32],
        old_descriptor_hash: [u8; 32],
        new_descriptor_hash: [u8; 32],
        new_version: u32,
    },
    XpubAnnounced {
        share_index: u16,
        recovery_xpubs: Vec<AnnouncedXpub>,
    },
    HealthCheckComplete {
        group_pubkey: [u8; 32],
        responsive: Vec<u16>,
        unresponsive: Vec<u16>,
    },
    PsbtProposed {
        session_id: [u8; 32],
        tier_index: u32,
    },
    PsbtSignatureNeeded {
        session_id: [u8; 32],
        tier_index: u32,
        initiator_pubkey: PublicKey,
    },
    PsbtSignatureReceived {
        session_id: [u8; 32],
        signer: crate::psbt_session::SignerId,
        signature_count: usize,
        threshold: u32,
    },
    PsbtFinalized {
        session_id: [u8; 32],
        txid: Option<[u8; 32]>,
    },
    PsbtAborted {
        session_id: [u8; 32],
        reason: String,
    },
}

impl std::fmt::Debug for KfpNodeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdhComplete { session_id, .. } => f
                .debug_struct("EcdhComplete")
                .field("session_id", &hex::encode(session_id))
                .field("shared_secret", &"[REDACTED]")
                .finish(),
            Self::PeerDiscovered { share_index, name } => f
                .debug_struct("PeerDiscovered")
                .field("share_index", share_index)
                .field("name", name)
                .finish(),
            Self::PeerOffline { share_index } => f
                .debug_struct("PeerOffline")
                .field("share_index", share_index)
                .finish(),
            Self::SigningStarted { session_id } => f
                .debug_struct("SigningStarted")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::SignatureComplete {
                session_id,
                signature,
            } => f
                .debug_struct("SignatureComplete")
                .field("session_id", &hex::encode(session_id))
                .field("signature", &hex::encode(signature))
                .finish(),
            Self::SigningFailed {
                session_id,
                error,
                code,
                offending_index,
            } => f
                .debug_struct("SigningFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .field("code", code)
                .field("offending_index", offending_index)
                .finish(),
            Self::EcdhFailed { session_id, error } => f
                .debug_struct("EcdhFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::OprfEvalRequested {
                session_id,
                requester_index,
            } => f
                .debug_struct("OprfEvalRequested")
                .field("session_id", &hex::encode(session_id))
                .field("requester_index", requester_index)
                .finish(),
            Self::OprfUnlockComplete { session_id, .. } => f
                .debug_struct("OprfUnlockComplete")
                .field("session_id", &hex::encode(session_id))
                .field("luks_key", &"[REDACTED]")
                .finish(),
            Self::OprfUnlockFailed { session_id, error } => f
                .debug_struct("OprfUnlockFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::OprfShareReceived {
                dealer_index,
                threshold,
                total,
                ..
            } => f
                .debug_struct("OprfShareReceived")
                .field("dealer_index", dealer_index)
                .field("threshold", threshold)
                .field("total", total)
                .field("share", &"[REDACTED]")
                .finish(),
            Self::OprfEnrollComplete { session_id } => f
                .debug_struct("OprfEnrollComplete")
                .field("session_id", &hex::encode(session_id))
                .finish(),
            Self::OprfEnrollFailed { session_id, error } => f
                .debug_struct("OprfEnrollFailed")
                .field("session_id", &hex::encode(session_id))
                .field("error", error)
                .finish(),
            Self::DescriptorProposed { session_id } => f
                .debug_struct("DescriptorProposed")
                .field("session_id", &hex::encode(session_id))
                .finish(),
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
            Self::DescriptorMigrateReceived {
                session_id,
                group_pubkey,
                old_descriptor_hash,
                new_descriptor_hash,
                new_version,
            } => f
                .debug_struct("DescriptorMigrateReceived")
                .field("session_id", &hex::encode(session_id))
                .field("group_pubkey", &hex::encode(group_pubkey))
                .field("old_descriptor_hash", &hex::encode(old_descriptor_hash))
                .field("new_descriptor_hash", &hex::encode(new_descriptor_hash))
                .field("new_version", new_version)
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
                group_pubkey,
                responsive,
                unresponsive,
            } => f
                .debug_struct("HealthCheckComplete")
                .field("group_pubkey", &hex::encode(group_pubkey))
                .field("responsive", responsive)
                .field("unresponsive", unresponsive)
                .finish(),
            Self::PsbtProposed {
                session_id,
                tier_index,
            } => f
                .debug_struct("PsbtProposed")
                .field("session_id", &hex::encode(session_id))
                .field("tier_index", tier_index)
                .finish(),
            Self::PsbtSignatureNeeded {
                session_id,
                tier_index,
                ..
            } => f
                .debug_struct("PsbtSignatureNeeded")
                .field("session_id", &hex::encode(session_id))
                .field("tier_index", tier_index)
                .finish(),
            Self::PsbtSignatureReceived {
                session_id,
                signer,
                signature_count,
                threshold,
            } => f
                .debug_struct("PsbtSignatureReceived")
                .field("session_id", &hex::encode(session_id))
                .field("signer", signer)
                .field("signature_count", signature_count)
                .field("threshold", threshold)
                .finish(),
            Self::PsbtFinalized { session_id, txid } => f
                .debug_struct("PsbtFinalized")
                .field("session_id", &hex::encode(session_id))
                .field("txid", &txid.map(hex::encode))
                .finish(),
            Self::PsbtAborted { session_id, reason } => f
                .debug_struct("PsbtAborted")
                .field("session_id", &hex::encode(session_id))
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Map key is `(session_id, new_descriptor_hash)`; value is `created_at`.
pub(crate) type SeenDescriptorMigrates = RwLock<HashMap<([u8; 32], [u8; 32]), u64>>;

pub struct KfpNode {
    pub(crate) keys: Keys,
    pub(crate) client: Client,
    pub(crate) share: SharePackage,
    pub(crate) group_pubkey: [u8; 32],
    pub(crate) sessions: Arc<RwLock<SessionManager>>,
    pub(crate) nonce_pool: NoncePool,
    pub(crate) ecdh_sessions: Arc<RwLock<EcdhSessionManager>>,
    /// Dedicated OPRF key share for the threshold-OPRF unlock. SEPARATE from the
    /// FROST signing share: the holder applies this via
    /// `keep_core::oprf::unlock::evaluate`, never the signing share. `None` on a
    /// node that is not an OPRF holder, which then ignores eval requests.
    pub(crate) oprf_key_share: Option<keep_core::oprf::threshold::KeyShare>,
    /// Box-side OPRF unlock sessions (initiator only). Holders keep no session.
    pub(crate) oprf_sessions: Arc<RwLock<OprfUnlockSessionManager>>,
    /// Per-requester sliding-window limiter guarding the holder eval oracle.
    pub(crate) oprf_rate_limiter: Arc<RwLock<OprfEvalRateLimiter>>,
    /// Dealer-side OPRF enrollment sessions (trusted-dealer share distribution).
    pub(crate) enroll_sessions: Arc<RwLock<OprfEnrollSessionManager>>,
    /// Holder-side pin of the only share index allowed to deal an OPRF enrollment to this node.
    /// `None` requires an explicit opt-out (`allow_unpinned_oprf_dealer`) and otherwise refuses
    /// enrollment fail-closed; setting it (to the box's index) refuses a share from any peer
    /// other than the designated dealer.
    pub(crate) expected_oprf_dealer: Option<u16>,
    /// Holder-side opt-out for the fail-closed dealer pin. In a trusted-dealer model only the box
    /// should deal shares, so with no `expected_oprf_dealer` pinned enrollment is refused unless
    /// this is explicitly set, which keeps the default secure while preserving open-enrollment
    /// flows (e.g. tests) that knowingly accept a share from any attested, authorized peer.
    pub(crate) allow_unpinned_oprf_dealer: bool,
    /// Resolved session timeout (configured or default). The dealer derives its enrollment/unlock
    /// ack wait from this so a short session timeout cannot expire the session before the wait,
    /// stranding completion. See [`KfpNode::dealer_wait_timeout`].
    pub(crate) session_timeout: Duration,
    pub(crate) descriptor_sessions: Arc<RwLock<DescriptorSessionManager>>,
    pub(crate) psbt_sessions: Arc<RwLock<PsbtSessionManager>>,
    pub(crate) peers: Arc<RwLock<PeerManager>>,
    pub(crate) policies: Arc<RwLock<HashMap<PublicKey, PeerPolicy>>>,
    pub(crate) hooks: RwLock<Arc<dyn SigningHooks>>,
    pub(crate) event_tx: broadcast::Sender<KfpNodeEvent>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: TokioMutex<Option<mpsc::Receiver<()>>>,
    pub(crate) replay_window_secs: u64,
    pub(crate) audit_log: Arc<SigningAuditLog>,
    expected_pcrs: Option<ExpectedPcrs>,
    /// Pinned policy for verifying peer TPM-quote attestation evidence. The
    /// parallel to `expected_pcrs` for the Nitro path; `None` means TPM quotes
    /// are not configured and appraise to `NotConfigured`.
    tpm_attestation_policy: Option<TpmAttestationPolicy>,
    /// Producer side: when set, every announce carries a fresh TPM quote bound to
    /// it. `None` means this node attaches no TPM attestation to its announces.
    announce_attestor: Option<Arc<dyn AnnounceAttestor>>,
    /// In-flight background re-announce, if any. Holds at most one task: a new
    /// `spawn_announce` is suppressed while this one is unfinished, so a slow TPM
    /// quote cannot pile up concurrent quotes, concurrent signing-share copies,
    /// or emit duplicate same-second announces. Aborted both when `run` exits and
    /// on drop; the abort is best-effort cancellation (the task ends on its next
    /// poll, so an announce already mid-send may still reach the relay) that bounds
    /// how long a queued announce keeps its share copy alive after shutdown.
    announce_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) seen_xpub_announces: RwLock<HashSet<(u16, u64, [u8; 32])>>,
    /// Per-peer de-duplication for `NonceCommitment` broadcasts, keyed by
    /// `(share_index, content_hash)` where `content_hash` covers the sorted
    /// nonce_id/commitment set. Keying on content rather than the sender
    /// controlled `created_at` avoids dropping distinct same-second batches and
    /// stops a peer forcing repeated secp256k1 deserialization by perturbing the
    /// timestamp. Value is `created_at` for time-based retention.
    pub(crate) seen_nonce_commitments: RwLock<HashMap<(u16, [u8; 32]), u64>>,
    /// Holder-side de-duplication for `OprfEnroll` deliveries, keyed by
    /// `(dealer_index, session_id)` so a relay redelivering the same enrollment
    /// inside the replay window cannot re-emit live key material on the broadcast
    /// bus or re-ack. The `dealer_index` is bound to the sender pubkey by
    /// `verify_peer_share_index` before insertion. Value is `created_at` for
    /// replay-window pruning.
    pub(crate) seen_oprf_enrolls: RwLock<HashMap<(u16, [u8; 32]), u64>>,
    /// Per-session de-duplication for `DescriptorMigrate` link broadcasts.
    /// Keyed by `(session_id, new_descriptor_hash)` so an attacker cannot
    /// bypass dedupe by perturbing `created_at`. Value is `created_at` for
    /// replay-window pruning.
    pub(crate) seen_descriptor_migrates: SeenDescriptorMigrates,
    pub(crate) descriptor_proposers: RwLock<HashSet<u16>>,
    pub(crate) psbt_proposers: RwLock<HashSet<u16>>,
    pub(crate) local_recovery_xpubs: RwLock<Vec<AnnouncedXpub>>,
    pub(crate) descriptor_lookup: Option<Arc<dyn PersistedDescriptorLookup>>,
    pub(crate) recovery_signer_registry:
        Option<Arc<dyn crate::recovery_signers::RecoverySignerRegistry>>,
}

impl Drop for KfpNode {
    fn drop(&mut self) {
        // `KeyShare` is `Copy + Zeroize` but not `ZeroizeOnDrop`, so the stored OPRF key share
        // would otherwise linger in memory after the node is released. Wipe it explicitly.
        if let Some(share) = self.oprf_key_share.as_mut() {
            use zeroize::Zeroize;
            share.zeroize();
        }
        // If `run` was cancelled (its future dropped) rather than shutdown-signalled,
        // its run-exit abort never ran; cancel any orphaned announce task here so it
        // stops holding its `Zeroizing` signing-share copy.
        if let Some(handle) = self
            .announce_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            handle.abort();
        }
    }
}

/// Strip control characters, clamp to `MAX_NACK_REASON_LENGTH`, and return a
/// placeholder when the result is empty. Shared between descriptor and PSBT
/// coordination paths, which both accept peer-supplied reason strings.
pub(crate) fn sanitize_reason(reason: &str) -> String {
    let mut sanitized = String::new();
    for c in reason.chars().filter(|c| !c.is_control()) {
        if sanitized.len() + c.len_utf8() > MAX_NACK_REASON_LENGTH {
            break;
        }
        sanitized.push(c);
    }
    if sanitized.is_empty() {
        "no reason given".to_string()
    } else {
        sanitized
    }
}

/// Owned inputs for building and sending one announce, extracted from a
/// `&KfpNode` so the slow part (TPM quote + relay send) can run off the node's
/// event loop without borrowing it. The `SharePackage` is `ZeroizeOnDrop` and
/// not `Clone`, so its signing share is serialized here into a `Zeroizing`
/// buffer wiped on drop. Running off-loop trades away the old ordering that
/// produced the quote *before* materializing the share: this copy is now
/// resident for the full quote round-trip (up to `ANNOUNCE_QUOTE_TIMEOUT`).
/// The marginal exposure is bounded: the original share is resident in
/// `self.share` for the node's lifetime regardless, and `spawn_announce`'s
/// single-flight guard keeps at most one such copy alive at a time.
/// The same bounded-exposure argument covers the `keys` clone: it carries the
/// Nostr identity secret and is resident for the same quote round-trip, but the
/// original is held in `self.keys` for the node's lifetime regardless and the
/// single-flight guard bounds it to one copy at a time.
struct AnnounceJob {
    keys: Keys,
    client: Client,
    group_pubkey: [u8; 32],
    share_index: u16,
    name: String,
    signing_share: Zeroizing<[u8; 32]>,
    verifying_share: [u8; 33],
    attestor: Option<Arc<dyn AnnounceAttestor>>,
}

impl KfpNode {
    pub async fn new(share: SharePackage, relays: Vec<String>) -> Result<Self> {
        Self::with_nonce_store(share, relays, None, None, None).await
    }

    pub async fn new_with_proxy(
        share: SharePackage,
        relays: Vec<String>,
        proxy: SocketAddr,
    ) -> Result<Self> {
        Self::with_nonce_store(share, relays, None, Some(proxy), None).await
    }

    pub async fn with_nonce_store_path(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store_path: &Path,
    ) -> Result<Self> {
        let store = FileNonceStore::new(nonce_store_path)?;
        Self::with_nonce_store(
            share,
            relays,
            Some(Arc::new(store) as Arc<dyn NonceStore>),
            None,
            None,
        )
        .await
    }

    pub async fn with_nonce_store(
        share: SharePackage,
        relays: Vec<String>,
        nonce_store: Option<Arc<dyn NonceStore>>,
        proxy: Option<SocketAddr>,
        session_timeout: Option<Duration>,
    ) -> Result<Self> {
        let descriptor_manager = match session_timeout {
            Some(t) => DescriptorSessionManager::with_timeout(t)?,
            None => DescriptorSessionManager::new(),
        };

        let psbt_manager = match session_timeout {
            Some(t) => PsbtSessionManager::with_timeout(t)?,
            None => PsbtSessionManager::new(),
        };

        for relay in &relays {
            let validate = if ALLOW_INTERNAL_HOSTS {
                validate_relay_url_allow_internal
            } else {
                validate_relay_url
            };
            validate(relay).map_err(|e| {
                FrostNetError::Transport(format!("Rejected relay URL {relay}: {e}"))
            })?;
        }

        let keys = derive_keys_from_share(&share)?;
        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };

        let relay_opts = default_relay_opts();

        for relay in &relays {
            client
                .pool()
                .add_relay(relay, relay_opts.clone())
                .await
                .map_err(|e| {
                    FrostNetError::Transport(format!("Failed to add relay {relay}: {e}"))
                })?;
        }

        client.connect().await;

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let relay_map = client.relays().await;
                let any_connected = relay_map
                    .values()
                    .any(|r| matches!(r.status(), RelayStatus::Connected));
                if any_connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| FrostNetError::Transport("Timed out waiting for relay connection".into()))?;

        let group_pubkey = *share.group_pubkey();
        let our_index = share.metadata.identifier;
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let mut session_manager = match nonce_store {
            Some(store) => {
                info!(
                    consumed_count = store.count(),
                    "Loaded nonce consumption store"
                );
                SessionManager::new().with_nonce_store(store)
            }
            None => SessionManager::new(),
        };
        if let Some(t) = session_timeout {
            session_manager = session_manager.with_timeout(t);
        }

        let ecdh_manager = match session_timeout {
            Some(t) => EcdhSessionManager::new().with_timeout(t),
            None => EcdhSessionManager::new(),
        };

        let oprf_manager = match session_timeout {
            Some(t) => OprfUnlockSessionManager::new().with_timeout(t),
            None => OprfUnlockSessionManager::new(),
        };

        let enroll_manager = match session_timeout {
            Some(t) => OprfEnrollSessionManager::new().with_timeout(t),
            None => OprfEnrollSessionManager::new(),
        };
        // Mirror the managers' own default so the dealer ack wait tracks the
        // configured session lifetime rather than a hardcoded constant.
        let resolved_session_timeout = session_timeout.unwrap_or(Duration::from_secs(30));

        let audit_hmac_key = derive_audit_hmac_key(&keys, &group_pubkey);
        let audit_log = Arc::new(SigningAuditLog::new(audit_hmac_key));

        Ok(Self {
            keys,
            client,
            share,
            group_pubkey,
            sessions: Arc::new(RwLock::new(session_manager)),
            nonce_pool: NoncePool::new(),
            ecdh_sessions: Arc::new(RwLock::new(ecdh_manager)),
            oprf_key_share: None,
            oprf_sessions: Arc::new(RwLock::new(oprf_manager)),
            oprf_rate_limiter: Arc::new(RwLock::new(OprfEvalRateLimiter::new())),
            enroll_sessions: Arc::new(RwLock::new(enroll_manager)),
            expected_oprf_dealer: None,
            allow_unpinned_oprf_dealer: false,
            session_timeout: resolved_session_timeout,
            descriptor_sessions: Arc::new(RwLock::new(descriptor_manager)),
            psbt_sessions: Arc::new(RwLock::new(psbt_manager)),
            peers: Arc::new(RwLock::new(PeerManager::new(our_index))),
            policies: Arc::new(RwLock::new(HashMap::new())),
            hooks: RwLock::new(Arc::new(NoOpHooks)),
            event_tx,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx: TokioMutex::new(Some(shutdown_rx)),
            replay_window_secs: DEFAULT_REPLAY_WINDOW_SECS,
            audit_log,
            expected_pcrs: None,
            tpm_attestation_policy: None,
            announce_attestor: None,
            announce_task: std::sync::Mutex::new(None),
            seen_xpub_announces: RwLock::new(HashSet::new()),
            seen_nonce_commitments: RwLock::new(HashMap::new()),
            seen_oprf_enrolls: RwLock::new(HashMap::new()),
            seen_descriptor_migrates: RwLock::new(HashMap::new()),
            descriptor_proposers: RwLock::new(HashSet::new()),
            psbt_proposers: RwLock::new(HashSet::new()),
            local_recovery_xpubs: RwLock::new(Vec::new()),
            descriptor_lookup: None,
            recovery_signer_registry: None,
        })
    }

    pub fn with_descriptor_lookup(mut self, lookup: Arc<dyn PersistedDescriptorLookup>) -> Self {
        self.descriptor_lookup = Some(lookup);
        self
    }

    /// Attach a registry mapping recovery-tier xpub fingerprints to external
    /// NIP-46 signers. Callers handling `PsbtSignatureNeeded` events use
    /// `resolve_recovery_signer` to look up the configured bunker URI for a
    /// given fingerprint.
    pub fn with_recovery_signer_registry(
        mut self,
        registry: Arc<dyn crate::recovery_signers::RecoverySignerRegistry>,
    ) -> Self {
        self.recovery_signer_registry = Some(registry);
        self
    }

    /// Resolve a recovery-tier xpub fingerprint to a registered external
    /// signer, or `None` if no registry is attached or the fingerprint has
    /// no entry.
    pub fn resolve_recovery_signer(
        &self,
        fingerprint: &str,
    ) -> Option<crate::recovery_signers::RecoverySignerHandle> {
        self.recovery_signer_registry
            .as_ref()
            .and_then(|r| r.resolve(fingerprint))
    }

    pub fn with_descriptor_session_store(
        self,
        store: Arc<dyn crate::descriptor_session::DescriptorSessionStore>,
    ) -> Self {
        {
            let mut sessions = self.descriptor_sessions.write();
            sessions.set_store(store);
            match sessions.load_persisted_sessions() {
                Ok(count) if count > 0 => {
                    info!(count, "Restored persisted descriptor sessions");
                }
                Err(e) => {
                    warn!("Failed to load persisted descriptor sessions: {e}");
                }
                _ => {}
            }
        }
        self
    }

    pub fn with_expected_pcrs(mut self, pcrs: ExpectedPcrs) -> Self {
        self.expected_pcrs = Some(pcrs);
        self
    }

    pub fn set_expected_pcrs(&mut self, pcrs: ExpectedPcrs) {
        self.expected_pcrs = Some(pcrs);
    }

    pub fn with_tpm_attestation_policy(mut self, policy: TpmAttestationPolicy) -> Self {
        self.tpm_attestation_policy = Some(policy);
        self
    }

    pub fn set_tpm_attestation_policy(&mut self, policy: TpmAttestationPolicy) {
        self.tpm_attestation_policy = Some(policy);
    }

    /// Attach a TPM quote, produced by `attestor`, to every announce this node
    /// makes. The producer side of [`with_tpm_attestation_policy`]; see
    /// [`AnnounceAttestor`].
    pub fn with_announce_attestor(mut self, attestor: Arc<dyn AnnounceAttestor>) -> Self {
        self.announce_attestor = Some(attestor);
        self
    }

    pub fn set_announce_attestor(&mut self, attestor: Arc<dyn AnnounceAttestor>) {
        self.announce_attestor = Some(attestor);
    }

    pub fn require_attestation(&self) -> bool {
        self.expected_pcrs.is_some() || self.tpm_attestation_policy.is_some()
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn share_index(&self) -> u16 {
        self.share.metadata.identifier
    }

    /// The node's already-decrypted share material, held in memory since init.
    /// Lets callers build a local signer without re-reading and re-decrypting
    /// from storage (which, on mobile, requires a biometric-gated key that is
    /// unavailable in a background service context).
    pub fn share_package(&self) -> &SharePackage {
        &self.share
    }

    /// Test-only: inject a fully-formed descriptor session directly into the
    /// node's session manager. Used by integration tests that need a
    /// `Complete` migration session as a precondition for sweep coordination,
    /// without running the full descriptor proposal/contribute/finalize/ACK
    /// flow.
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub fn test_inject_descriptor_session(
        &self,
        session: crate::descriptor_session::DescriptorSession,
    ) {
        self.descriptor_sessions
            .write()
            .test_insert_session(session);
    }

    /// Test-only: inject a peer directly into the peer table, bypassing the
    /// announce/proof-of-share flow. Used by OPRF integration tests that need a
    /// requester peer present with a specific `AttestationStatus` (e.g.
    /// `Verified`) without standing up the full attestation machinery.
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub fn test_inject_peer(&self, peer: Peer) {
        self.peers.write().add_peer(peer);
    }

    /// Test-only: override the attestation status of an already-known peer. The
    /// happy-path OPRF test discovers peers naturally, then flips the requester's
    /// status to `Verified` to satisfy the holder's strict attestation gate.
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub fn test_set_peer_attestation(&self, share_index: u16, status: AttestationStatus) {
        if let Some(peer) = self.peers.write().get_peer_mut(share_index) {
            peer.attestation_status = status;
        }
    }

    /// Test-only: run the attestation-evidence dispatch for an announce payload,
    /// to assert the appraised status (e.g. that unappraisable cross-type evidence
    /// is `Failed`, not silently `NotConfigured`).
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub fn test_attestation_status(&self, payload: &AnnouncePayload) -> AttestationStatus {
        self.verify_announce_attestation(payload)
    }

    /// Test-only: drive the holder-side OPRF eval handler directly. Lets the
    /// negative-path tests assert on the returned `Result` (gate rejections,
    /// rate limiting, replay) without a full box round-trip.
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_handle_oprf_eval_request(
        &self,
        from: PublicKey,
        request: OprfEvalRequestPayload,
    ) -> Result<()> {
        self.handle_oprf_eval_request(from, request).await
    }

    /// Test-only: drive the holder-side OPRF enrollment handler directly. Lets the
    /// gate tests assert on the returned `Result` (attestation, replay, policy)
    /// without a full dealer round-trip.
    #[doc(hidden)]
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_handle_oprf_enroll(
        &self,
        from: PublicKey,
        payload: OprfEnrollPayload,
    ) -> Result<()> {
        self.handle_oprf_enroll(from, payload).await
    }

    pub fn set_replay_window(&mut self, secs: u64) {
        self.replay_window_secs = secs;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<KfpNodeEvent> {
        self.event_tx.subscribe()
    }

    pub fn audit_log(&self) -> &SigningAuditLog {
        &self.audit_log
    }

    pub fn online_peers(&self) -> usize {
        self.peers.read().online_count()
    }

    /// Number of our own pre-generated nonces currently available in the pool.
    pub fn nonce_pool_own_available(&self) -> usize {
        self.nonce_pool.own_available()
    }

    /// Number of pre-exchanged commitments pooled for the given peer.
    pub fn nonce_pool_peer_available(&self, share_index: u16) -> usize {
        self.nonce_pool.peer_available(share_index)
    }

    pub fn peer_status(&self) -> Vec<(u16, PeerStatus, Option<String>, PublicKey)> {
        let peers = self.peers.read();
        let threshold = peers.offline_threshold();
        peers
            .all_peers()
            .iter()
            .map(|p| {
                // Report presence from the last-seen timeout, not the stored
                // status flag: a peer that simply stops announcing is never
                // explicitly marked offline, so the raw flag would stay
                // "online" forever (showing a vanished co-signer as available).
                let status = if p.is_online(threshold) {
                    PeerStatus::Online
                } else {
                    PeerStatus::Offline
                };
                (p.share_index, status, p.name.clone(), p.pubkey)
            })
            .collect()
    }

    pub fn set_peer_policy(&self, policy: PeerPolicy) {
        self.policies.write().insert(policy.pubkey, policy);
    }

    pub fn remove_peer_policy(&self, pubkey: &PublicKey) {
        self.policies.write().remove(pubkey);
    }

    pub fn get_peer_policy(&self, pubkey: &PublicKey) -> Option<PeerPolicy> {
        self.policies.read().get(pubkey).cloned()
    }

    pub async fn announce_xpubs(&self, recovery_xpubs: Vec<AnnouncedXpub>) -> Result<()> {
        let peer_pubkeys: Vec<PublicKey> = {
            let peers = self.peers.read();
            peers
                .get_online_peers()
                .iter()
                .filter(|p| self.can_send_to(&p.pubkey))
                .map(|p| p.pubkey)
                .collect()
        };

        // Canonicalize fingerprints to lowercase before persisting or sending
        // so protocol equality checks stay case-sensitive without surprises.
        let recovery_xpubs: Vec<AnnouncedXpub> = recovery_xpubs
            .into_iter()
            .map(|mut x| {
                x.fingerprint = x.fingerprint.to_ascii_lowercase();
                x
            })
            .collect();

        *self.local_recovery_xpubs.write() = recovery_xpubs.clone();

        let xpub_count = recovery_xpubs.len();
        let payload = XpubAnnouncePayload::new(
            self.group_pubkey,
            self.share.metadata.identifier,
            recovery_xpubs,
        );

        KfpMessage::XpubAnnounce(payload.clone())
            .validate()
            .map_err(|e| FrostNetError::Protocol(e.to_string()))?;

        let mut fail_count = 0usize;
        for pubkey in &peer_pubkeys {
            let event = KfpEventBuilder::xpub_announce(&self.keys, pubkey, payload.clone())?;
            if let Err(e) = self.client.send_event(&event).await {
                warn!(peer = %pubkey, error = %e, "Failed to send xpub announcement");
                fail_count += 1;
            }
        }
        if fail_count == peer_pubkeys.len() && !peer_pubkeys.is_empty() {
            return Err(FrostNetError::Transport(
                "Failed to send xpub announcement to any peer".into(),
            ));
        }

        info!(
            share_index = self.share.metadata.identifier,
            xpub_count,
            peer_count = peer_pubkeys.len(),
            "Announced recovery xpubs"
        );
        Ok(())
    }

    pub fn get_peer_recovery_xpubs(&self, share_index: u16) -> Option<Vec<AnnouncedXpub>> {
        self.peers
            .read()
            .get_peer_recovery_xpubs(share_index)
            .map(|xpubs| xpubs.to_vec())
    }

    /// Install this node's dedicated OPRF key share, making it an OPRF-unlock
    /// holder and enabling `request_oprf_unlock` as an initiator. This is a
    /// separate key from the FROST signing share; the holder applies it only via
    /// `keep_core::oprf::unlock::evaluate`.
    pub fn set_oprf_key_share(&mut self, share: keep_core::oprf::threshold::KeyShare) {
        self.oprf_key_share = Some(share);
    }

    /// Builder form of [`set_oprf_key_share`](Self::set_oprf_key_share).
    pub fn with_oprf_key_share(mut self, share: keep_core::oprf::threshold::KeyShare) -> Self {
        self.oprf_key_share = Some(share);
        self
    }

    /// Pin the only share index permitted to deal an OPRF enrollment to this node (the box). When
    /// set, `handle_oprf_enroll` refuses a share from any other peer, even an attested one, so a
    /// compromised-but-attested group member cannot poison or overwrite this holder's share.
    pub fn with_expected_oprf_dealer(mut self, dealer_index: u16) -> Self {
        self.expected_oprf_dealer = Some(dealer_index);
        self
    }

    /// Setter form of [`with_expected_oprf_dealer`](Self::with_expected_oprf_dealer).
    pub fn set_expected_oprf_dealer(&mut self, dealer_index: u16) {
        self.expected_oprf_dealer = Some(dealer_index);
    }

    /// Opt out of the fail-closed dealer pin: accept an OPRF enrollment share from any attested,
    /// authorized peer when no `expected_oprf_dealer` is pinned. The default refuses unpinned
    /// enrollment because in a trusted-dealer model only the box should deal shares; set this only
    /// for deliberate open-enrollment flows that accept that weaker trust assumption.
    pub fn allow_unpinned_oprf_dealer(mut self, allow: bool) -> Self {
        self.allow_unpinned_oprf_dealer = allow;
        self
    }

    /// Setter form of [`allow_unpinned_oprf_dealer`](Self::allow_unpinned_oprf_dealer).
    pub fn set_allow_unpinned_oprf_dealer(&mut self, allow: bool) {
        self.allow_unpinned_oprf_dealer = allow;
    }

    /// Dealer-side wait for enrollment/unlock acks, derived from the configured session timeout so
    /// the wait and the session lifetime stay coupled: a short session timeout would otherwise
    /// expire the session before a hardcoded 30s wait elapsed, so the final ack would be refused as
    /// expired and completion would never fire.
    pub(crate) fn dealer_wait_timeout(&self) -> Duration {
        self.session_timeout
    }

    /// Holder-side bound on the inline wait for OPRF seal confirmation: the smaller of
    /// [`OPRF_SEAL_CONFIRM_TIMEOUT`] and half the session timeout, so a very short configured
    /// session timeout shrinks the wait too and the ack always lands inside the dealer's ack-wait
    /// window rather than arriving after the session has already expired.
    pub(crate) fn seal_confirm_timeout(&self) -> Duration {
        OPRF_SEAL_CONFIRM_TIMEOUT.min(self.session_timeout / 2)
    }

    pub fn set_descriptor_proposers(&self, indices: HashSet<u16>) {
        *self.descriptor_proposers.write() = indices;
    }

    pub fn descriptor_proposers(&self) -> HashSet<u16> {
        self.descriptor_proposers.read().clone()
    }

    pub fn set_psbt_proposers(&self, indices: HashSet<u16>) {
        *self.psbt_proposers.write() = indices;
    }

    pub fn psbt_proposers(&self) -> HashSet<u16> {
        self.psbt_proposers.read().clone()
    }

    pub fn set_hooks(&self, hooks: Arc<dyn SigningHooks>) {
        *self.hooks.write() = hooks;
    }

    pub(crate) fn can_send_to(&self, pubkey: &PublicKey) -> bool {
        self.policies
            .read()
            .get(pubkey)
            .is_none_or(|p| p.allow_send)
    }

    pub(crate) fn can_receive_from(&self, pubkey: &PublicKey) -> bool {
        self.policies
            .read()
            .get(pubkey)
            .is_none_or(|p| p.allow_receive)
    }

    pub(crate) fn invoke_post_sign_hook(&self, session_id: &[u8; 32], signature: &[u8; 64]) {
        let info = {
            let mut sessions = self.sessions.write();
            let info = sessions.get_session(session_id).map(SessionInfo::from);
            if info.is_some() {
                sessions.complete_session(session_id);
            }
            info
        };

        if let Some(info) = info {
            let hooks = self.hooks.read().clone();
            hooks.post_sign(&info, signature);
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn select_eligible_peers(
        &self,
        threshold: usize,
        exclude: &[u16],
    ) -> Result<(Vec<u16>, Vec<(u16, PublicKey)>)> {
        let selected_peers: Vec<Peer> = {
            let peers = self.peers.read();
            let eligible_peers: Vec<_> = peers
                .get_signing_peers()
                .into_iter()
                .filter(|p| !exclude.contains(&p.share_index))
                .filter(|p| self.can_send_to(&p.pubkey) && self.can_receive_from(&p.pubkey))
                .collect();

            if eligible_peers.len() + 1 < threshold {
                return Err(FrostNetError::InsufficientPeers {
                    needed: threshold - 1,
                    available: eligible_peers.len(),
                });
            }

            eligible_peers
                .sample(&mut ::rand::rng(), threshold - 1)
                .copied()
                .cloned()
                .collect()
        };

        let participant_peers = selected_peers
            .iter()
            .map(|p| (p.share_index, p.pubkey))
            .collect();

        let mut participants: Vec<u16> = selected_peers.iter().map(|p| p.share_index).collect();
        participants.push(self.share.metadata.identifier);
        participants.sort();

        Ok((participants, participant_peers))
    }

    /// Extract everything needed to send one announce. Fast and synchronous (no
    /// TPM, no network), so it can run on the event loop without blocking it.
    fn announce_job(&self) -> Result<AnnounceJob> {
        let key_package = self
            .share
            .key_package()
            .map_err(|e| FrostNetError::Crypto(format!("Failed to get key package: {e}")))?;

        let verifying_share = key_package.verifying_share();
        let verifying_share_serialized = verifying_share.serialize().map_err(|e| {
            FrostNetError::Crypto(format!("Failed to serialize verifying share: {e}"))
        })?;
        let verifying_share: [u8; 33] = verifying_share_serialized
            .as_slice()
            .try_into()
            .map_err(|_| FrostNetError::Crypto("Invalid verifying share length".into()))?;

        let signing_share_serialized = Zeroizing::new(key_package.signing_share().serialize());
        let signing_share: Zeroizing<[u8; 32]> = Zeroizing::new(
            signing_share_serialized
                .as_slice()
                .try_into()
                .map_err(|_| FrostNetError::Crypto("Invalid signing share length".into()))?,
        );

        Ok(AnnounceJob {
            keys: self.keys.clone(),
            client: self.client.clone(),
            group_pubkey: self.group_pubkey,
            share_index: self.share.metadata.identifier,
            name: self.share.metadata.name.clone(),
            signing_share,
            verifying_share,
            attestor: self.announce_attestor.clone(),
        })
    }

    /// Produce the (optional) TPM quote bound to this announce, build the event,
    /// and send it. This is the slow part (the quote round-trips to a TPM), and
    /// it takes owned data so it can run in a spawned task off the event loop.
    /// Fail-closed: if quoting fails, no announce is sent (a configured-but-
    /// unattested announce would be rejected by any peer that pins a policy).
    async fn run_announce_job(job: AnnounceJob) -> Result<()> {
        let timestamp = Timestamp::now().as_secs();
        let tpm_attestation = match &job.attestor {
            Some(attestor) => {
                let nonce = derive_announce_attestation_nonce(
                    &job.group_pubkey,
                    job.share_index,
                    timestamp,
                );
                let evidence =
                    tokio::time::timeout(ANNOUNCE_QUOTE_TIMEOUT, attestor.request_quote(nonce))
                        .await
                        .map_err(|_| {
                            FrostNetError::Attestation("TPM quote service timed out".into())
                        })?
                        .map_err(|_| {
                            FrostNetError::Attestation("TPM quote service is unavailable".into())
                        })??;
                Some(evidence)
            }
            None => None,
        };

        let event = KfpEventBuilder::announcement(
            &job.keys,
            &job.group_pubkey,
            job.share_index,
            &job.signing_share,
            &job.verifying_share,
            Some(&job.name),
            timestamp,
            tpm_attestation,
        )?;

        job.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        info!(share_index = job.share_index, "Announced presence");
        Ok(())
    }

    /// Send one announce, awaiting completion. Used at startup so a quote failure
    /// fails the node fast (fail-closed) before it begins serving.
    pub async fn announce(&self) -> Result<()> {
        Self::run_announce_job(self.announce_job()?).await
    }

    /// Send one announce in the background, returning immediately. Used for the
    /// periodic and reciprocal re-announces so a slow TPM quote cannot stall the
    /// event loop (and with it every other inbound protocol message).
    fn spawn_announce(&self) {
        // Single-flight: while one background announce is still running, skip
        // spawning another. Both call sites (the periodic tick and the inbound
        // reciprocal-announce path) run on the node's `run` task, so this lock is
        // uncontended; it exists for interior mutability and the shutdown abort.
        // Without this, a burst of new-peer discoveries (or a tick overlapping a
        // slow quote) would spawn concurrent TPM quotes, hold several signing-
        // share copies at once, and emit duplicate same-second announces.
        let mut slot = self.announce_task.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        match self.announce_job() {
            Ok(job) => {
                *slot = Some(tokio::spawn(async move {
                    if let Err(e) = Self::run_announce_job(job).await {
                        warn!(error = %e, "Background re-announce failed");
                    }
                }));
            }
            Err(e) => {
                *slot = None;
                warn!(error = %e, "Failed to prepare re-announce");
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut shutdown_rx = self
            .shutdown_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| FrostNetError::Session("run() has already been started".into()))?;
        let mut notifications = self.client.notifications();

        let since = Timestamp::now() - Duration::from_secs(300);

        // Every group member's transport pubkey, derived from public data.
        // Scoping subscriptions to these `authors` (a) satisfies strict relays
        // that reject author-less filters (e.g. relay.nsec.app: "please add
        // authors or #p"), and (b) avoids pulling the relay's entire kind:24242
        // stream; that kind is shared with Blossom and other FROST groups, so
        // an unscoped filter floods the node and crowds out real signing
        // traffic. It also rejects spoofed group events from non-members.
        let authors = group_member_pubkeys(&self.group_pubkey, self.share.metadata.total_shares);

        let group_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .authors(authors.clone())
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::G),
                hex::encode(self.group_pubkey),
            )
            .since(since);

        let direct_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .authors(authors.clone())
            .pubkey(self.keys.public_key())
            .since(since);

        self.client
            .subscribe(group_filter.clone(), None)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        self.client
            .subscribe(direct_filter, None)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        let fetch_filter = Filter::new()
            .kind(Kind::Custom(KFP_EVENT_KIND))
            .authors(authors)
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::G),
                hex::encode(self.group_pubkey),
            )
            .since(since);

        match self
            .client
            .fetch_events(fetch_filter, Duration::from_secs(5))
            .await
        {
            Ok(events) => {
                let group_hex = hex::encode(self.group_pubkey);
                let matching: Vec<_> = events
                    .into_iter()
                    .filter(|e| {
                        e.tags
                            .filter(TagKind::custom("g"))
                            .any(|t| t.content() == Some(&group_hex))
                    })
                    .collect();
                debug!(count = matching.len(), "Fetched historical events");
                for event in matching {
                    let _ = self.handle_event(&event).await;
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to fetch historical events");
            }
        }

        self.announce().await?;

        // Re-announce often enough that an initiator with a short discovery
        // window reliably catches a periodic announce even if the immediate
        // reciprocal announce (see handle_announce) is missed. Must stay well
        // under the peer offline threshold so peers don't flap offline.
        let mut announce_interval = tokio::time::interval(crate::peer::peer_announce_interval());
        announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Reap expired sessions on roughly the signing round cadence so an
        // abandoned co-signer session (and its consumed single-use nonce) is
        // released promptly instead of lingering until lazy cleanup, which keeps
        // the session table and nonce pool from filling under a burst of
        // failovers where requesters abandon rounds after SIGNING_ROUND_TIMEOUT.
        let mut cleanup_interval = tokio::time::interval(SIGNING_ROUND_TIMEOUT);
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut replenish_interval = tokio::time::interval(Duration::from_secs(30));
        replenish_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = announce_interval.tick() => {
                    // Spawn so a slow TPM quote cannot stall the select loop.
                    self.spawn_announce();
                }
                _ = replenish_interval.tick() => {
                    if self.nonce_pool.own_deficit() > 0 {
                        if let Err(e) = self.replenish_nonce_pool().await {
                            warn!(error = %e, "Failed to replenish nonce pool");
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.sessions.write().cleanup_expired();
                    self.ecdh_sessions.write().cleanup_expired();
                    self.oprf_sessions.write().cleanup_expired();
                    self.enroll_sessions.write().cleanup_expired();
                    let expired = self.descriptor_sessions.write().cleanup_expired();
                    for (session_id, reason) in expired {
                        let _ = self.event_tx.send(KfpNodeEvent::DescriptorFailed {
                            session_id,
                            error: reason,
                        });
                    }
                    let expired_psbt = self.psbt_sessions.write().cleanup_expired();
                    for entry in expired_psbt {
                        if matches!(entry.kind, crate::psbt_session::ExpiredPsbtKind::Aborted) {
                            let _ = self.event_tx.send(KfpNodeEvent::PsbtAborted {
                                session_id: entry.session_id,
                                reason: entry.reason,
                            });
                        }
                    }
                    {
                        let now = Timestamp::now().as_secs();
                        let window = self.replay_window_secs + MAX_FUTURE_SKEW_SECS;
                        self.seen_xpub_announces.write().retain(|&(_, ts, _)| {
                            now.saturating_sub(window) <= ts
                        });
                        self.seen_nonce_commitments.write().retain(|_, ts| {
                            now.saturating_sub(window) <= *ts
                        });
                        self.seen_oprf_enrolls.write().retain(|_, ts| {
                            now.saturating_sub(window) <= *ts
                        });
                        self.seen_descriptor_migrates.write().retain(|_, ts| {
                            now.saturating_sub(window) <= *ts
                        });
                    }
                }
                notification = notifications.recv() => {
                    match notification {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            if let Err(e) = self.handle_event(&event).await {
                                warn!(error = %e, "Failed to handle event");
                            }
                        }
                        Ok(RelayPoolNotification::Shutdown) => {
                            info!("Relay pool shutdown");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Notification error");
                        }
                        _ => {}
                    }
                }
            }
        }

        // Cancel any in-flight background re-announce and await it, so its
        // `Zeroizing` share copy is dropped and wiped before `run` returns.
        // abort() takes effect at the task's next await point (an announce already
        // mid-`send_event` may still reach the relay); awaiting the handle bounds
        // that to completion rather than leaving the task running past `run`.
        let handle = self
            .announce_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }

    pub fn take_shutdown_handle(&mut self) -> Option<mpsc::Sender<()>> {
        self.shutdown_tx.take()
    }

    async fn handle_event(&self, event: &Event) -> Result<()> {
        if event.pubkey == self.keys.public_key() {
            return Ok(());
        }

        let msg_type = KfpEventBuilder::get_message_type(event);
        debug!(msg_type = ?msg_type, from = %event.pubkey, "Received event");

        let msg = match KfpEventBuilder::decrypt_message(&self.keys, event) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to decrypt/parse message");
                return Ok(());
            }
        };

        // Allowlist of initiating REQUESTS exempt from the trusted-peer requirement; each gates
        // itself by attestation/policy inside its handler. Every response/share/ack message,
        // including `OprfEnrollAck`, is deliberately absent so it still requires a trusted peer
        // (defense in depth), matching `EcdhShare` / `SignatureShare` / `OprfEvalShare` /
        // `DescriptorAck`. Do NOT add `OprfEnrollAck` here: that would exempt it from the gate.
        if !matches!(
            msg,
            KfpMessage::Announce(_)
                | KfpMessage::SignRequest(_)
                | KfpMessage::EcdhRequest(_)
                | KfpMessage::OprfEvalRequest(_)
                | KfpMessage::OprfEnroll(_)
        ) && !self.peers.read().is_trusted_peer(&event.pubkey)
        {
            debug!(from = %event.pubkey, "Rejecting message from untrusted peer");
            return Err(FrostNetError::UntrustedPeer(event.pubkey.to_string()));
        }

        match msg {
            KfpMessage::Announce(payload) => {
                self.handle_announce(event.pubkey, payload).await?;
            }
            KfpMessage::SignRequest(payload) => {
                self.handle_sign_request(event.pubkey, payload).await?;
            }
            KfpMessage::NonceCommitment(payload) => {
                self.handle_nonce_commitment(event.pubkey, payload).await?;
            }
            KfpMessage::Commitment(payload) => {
                self.handle_commitment(event.pubkey, payload).await?;
            }
            KfpMessage::SignatureShare(payload) => {
                self.handle_signature_share(event.pubkey, payload).await?;
            }
            KfpMessage::SignatureComplete(payload) => {
                self.handle_signature_complete(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::EcdhRequest(payload) => {
                self.handle_ecdh_request(event.pubkey, payload).await?;
            }
            KfpMessage::EcdhShare(payload) => {
                self.handle_ecdh_share(event.pubkey, payload).await?;
            }
            KfpMessage::EcdhComplete(payload) => {
                self.handle_ecdh_complete(event.pubkey, payload).await?;
            }
            KfpMessage::OprfEvalRequest(payload) => {
                self.handle_oprf_eval_request(event.pubkey, payload).await?;
            }
            KfpMessage::OprfEvalShare(payload) => {
                self.handle_oprf_eval_share(event.pubkey, payload).await?;
            }
            KfpMessage::OprfEnroll(payload) => {
                // Defense in depth: a share must arrive NIP-44 encrypted and directly addressed
                // to us. decrypt_message treats a non-addressed event's content as plaintext, so
                // require our `p` tag here; an addressed event that reached this point was
                // necessarily decrypted (a forged plaintext payload would have failed decryption).
                let addressed_to_us = event.tags.filter(TagKind::p()).any(|t| {
                    matches!(
                        t.as_standardized(),
                        Some(TagStandard::PublicKey { public_key, .. })
                            if public_key == &self.keys.public_key()
                    )
                });
                if !addressed_to_us {
                    debug!(from = %event.pubkey, "Rejecting OPRF enrollment: not directly addressed");
                    return Ok(());
                }
                self.handle_oprf_enroll(event.pubkey, payload).await?;
            }
            KfpMessage::OprfEnrollAck(payload) => {
                self.handle_oprf_enroll_ack(event.pubkey, payload).await?;
            }
            KfpMessage::RefreshRequest(_)
            | KfpMessage::RefreshRound1(_)
            | KfpMessage::RefreshRound2(_)
            | KfpMessage::RefreshComplete(_) => {
                if let Some(sid) = msg.session_id() {
                    warn!(session_id = %hex::encode(sid), "Distributed refresh not yet implemented");
                }
            }
            KfpMessage::DescriptorPropose(payload) => {
                self.handle_descriptor_propose(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorContribute(payload) => {
                self.handle_descriptor_contribute(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorFinalize(payload) => {
                self.handle_descriptor_finalize(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::DescriptorAck(payload) => {
                self.handle_descriptor_ack(event.pubkey, payload).await?;
            }
            KfpMessage::DescriptorNack(payload) => {
                self.handle_descriptor_nack(event.pubkey, payload).await?;
            }
            KfpMessage::DescriptorMigrate(payload) => {
                self.handle_descriptor_migrate(event.pubkey, payload)
                    .await?;
            }
            KfpMessage::XpubAnnounce(payload) => {
                self.handle_xpub_announce(event.pubkey, payload).await?;
            }
            KfpMessage::PsbtPropose(payload) => {
                self.handle_psbt_propose(event.pubkey, payload).await?;
            }
            KfpMessage::PsbtSign(payload) => {
                self.handle_psbt_sign(event.pubkey, payload).await?;
            }
            KfpMessage::PsbtFinalize(payload) => {
                self.handle_psbt_finalize(event.pubkey, payload).await?;
            }
            KfpMessage::PsbtAbort(payload) => {
                self.handle_psbt_abort(event.pubkey, payload).await?;
            }
            KfpMessage::Ping(payload) => {
                self.handle_ping(event.pubkey, payload).await?;
            }
            KfpMessage::Pong(payload) => {
                self.handle_pong(event.pubkey, payload).await?;
            }
            KfpMessage::Error(payload) => {
                warn!(
                    code = %payload.code,
                    message = %payload.message,
                    "Received error from peer"
                );
                // A session-scoped error from a participant means that peer
                // cannot continue the session (e.g. it no longer holds a
                // referenced pre-exchanged nonce). Surface it so an in-flight
                // `request_signature` fails fast instead of waiting for timeout.
                if let Some(session_id) = payload.session_id {
                    // Resolve the offending peer's share index so the requester
                    // can scope any pool cleanup to just that peer instead of
                    // wiping every peer's pooled commitments.
                    let offending_index = {
                        let sessions = self.sessions.read();
                        match sessions.get_session(&session_id) {
                            Some(session) => {
                                let peers = self.peers.read();
                                session.participants().iter().copied().find(|&idx| {
                                    peers
                                        .get_peer(idx)
                                        .map(|p| p.pubkey == event.pubkey)
                                        .unwrap_or(false)
                                })
                            }
                            None => None,
                        }
                    };
                    // Recoverable pre-exchange misses (`stale_nonce` /
                    // `incomplete_pre_exchange`) keep their fast-fail + pool-clear
                    // handling in `request_signature`. Any other peer-reported
                    // error is treated like an unresponsive peer there: the
                    // offending index is excluded and the round fails over to
                    // live co-signers instead of returning fatally, so a faulty
                    // or malicious peer cannot reliably block signing. The index
                    // is carried structurally; the human-readable string still
                    // embeds it for logs and external consumers.
                    let error = match offending_index {
                        Some(idx) => {
                            format!("Peer reported error: {} (peer {idx})", payload.code)
                        }
                        None => format!("Peer reported error: {}", payload.code),
                    };
                    let _ = self.event_tx.send(KfpNodeEvent::SigningFailed {
                        session_id,
                        error,
                        code: payload.code.clone(),
                        offending_index,
                    });
                }
            }
        }

        Ok(())
    }

    async fn handle_announce(&self, pubkey: PublicKey, payload: AnnouncePayload) -> Result<()> {
        if payload.group_pubkey != self.group_pubkey {
            return Ok(());
        }

        let now = Timestamp::now().as_secs();
        if payload.timestamp + ANNOUNCE_MAX_AGE_SECS < now {
            debug!(
                timestamp = payload.timestamp,
                now, "Rejecting stale announcement"
            );
            return Err(FrostNetError::Protocol(
                "Announcement timestamp too old".into(),
            ));
        }
        if payload.timestamp > now + ANNOUNCE_MAX_FUTURE_SECS {
            debug!(
                timestamp = payload.timestamp,
                now, "Rejecting future-dated announcement"
            );
            return Err(FrostNetError::Protocol(
                "Announcement timestamp in future".into(),
            ));
        }

        crate::proof::verify_proof(
            &payload.verifying_share,
            &payload.proof_signature,
            &payload.group_pubkey,
            payload.share_index,
            payload.timestamp,
        )?;

        // The attestation blobs sit outside `proof_signature`; their integrity rests on the
        // fail-closed admission below (AK pin plus nonce bound to the signed share_index/timestamp),
        // so unsigned or swapped evidence cannot be admitted.
        let attestation_status = self.verify_announce_attestation(&payload);

        // When the node requires attestation (any policy configured), admit a peer ONLY if its
        // attestation is `Verified`. This rejects `Failed`, `NotProvided`, and `NotConfigured`
        // alike, and is keyed on ALL configured policies (not just the Nitro `expected_pcrs`), so a
        // TPM-only node enforces admission and a peer cannot downgrade by presenting unappraisable
        // evidence of the wrong type.
        if self.require_attestation() && attestation_status != AttestationStatus::Verified {
            warn!(
                share_index = payload.share_index,
                status = ?attestation_status,
                "Rejecting peer: attestation not Verified (attestation required)"
            );
            return Err(FrostNetError::Attestation(format!(
                "Peer {} attestation not verified: {:?}",
                payload.share_index, attestation_status
            )));
        }

        let mut peer = Peer::new(pubkey, payload.share_index)
            .with_capabilities(payload.capabilities)
            .with_verifying_share(payload.verifying_share);

        if let Some(name) = payload.name {
            peer = peer.with_name(&name);
        }

        peer = peer.with_attestation_status(attestation_status);

        let is_new_peer = self.peers.read().get_peer(payload.share_index).is_none();

        let name_clone = peer.name.clone();
        self.peers.write().add_peer(peer);

        info!(
            share_index = payload.share_index,
            name = ?name_clone,
            "Peer discovered with valid proof-of-share"
        );

        let _ = self.event_tx.send(KfpNodeEvent::PeerDiscovered {
            share_index: payload.share_index,
            name: name_clone,
        });

        if is_new_peer {
            // Reciprocate our own announcement so the new peer discovers us
            // right away, instead of waiting for our next periodic re-announce.
            // Without this, an initiator's short discovery window can miss an
            // already-online co-signer. Gated on `is_new_peer` so the exchange
            // terminates: once a peer knows us, our announce no longer looks
            // new to it and it won't reciprocate again. Spawned so a slow TPM
            // quote cannot stall this inbound-event handler.
            self.spawn_announce();

            // A newly discovered peer may have come online after we last
            // replenished (whose broadcast only carries freshly generated
            // commitments). Send it our current pool so it can instant-sign
            // with us right away.
            if self.can_send_to(&pubkey) {
                if let Err(e) = self.send_nonce_pool_to(&pubkey).await {
                    warn!(peer = %pubkey, error = %e, "Failed to send nonce pool to new peer");
                }
            }
        }

        Ok(())
    }

    fn verify_announce_attestation(&self, payload: &AnnouncePayload) -> AttestationStatus {
        // The node "requires attestation" if it has configured ANY attestation policy. In that
        // mode, evidence of a type we cannot appraise (the matching policy is absent) is a
        // DOWNGRADE attempt and is rejected as `Failed`, never silently treated as `NotConfigured`
        // (which would be more permissive than presenting no evidence at all). `NotConfigured` is
        // reserved for a node that enforces no attestation whatsoever.
        let has_policy = self.require_attestation();

        // A peer presents one evidence type. When TPM-quote evidence is present it takes
        // precedence over (shadows) the enclave `attestation` field; this is safe because the
        // announce is self-signed (proof_signature over share_index + timestamp), so a network
        // attacker cannot swap or inject the evidence without breaking that signature.
        if let Some(ev) = &payload.tpm_attestation {
            return match &self.tpm_attestation_policy {
                Some(pol) => appraise_tpm_quote(
                    payload.share_index,
                    ev,
                    pol,
                    // Bind the quote to THIS announce (share index + timestamp), not just the group,
                    // so a valid quote cannot be replayed into a different/forged announce.
                    &derive_announce_attestation_nonce(
                        &self.group_pubkey,
                        payload.share_index,
                        payload.timestamp,
                    ),
                ),
                None if has_policy => AttestationStatus::Failed(
                    "TPM quote evidence presented but this node has no TPM attestation policy"
                        .to_string(),
                ),
                None => AttestationStatus::NotConfigured,
            };
        }

        if let Some(att) = &payload.attestation {
            return match &self.expected_pcrs {
                Some(pcrs) => match verify_peer_attestation(att, pcrs, &self.group_pubkey) {
                    Ok(()) => AttestationStatus::Verified,
                    Err(e) => AttestationStatus::Failed(e.to_string()),
                },
                None if has_policy => AttestationStatus::Failed(
                    "Enclave attestation presented but this node has no expected PCRs".to_string(),
                ),
                None => AttestationStatus::NotConfigured,
            };
        }

        AttestationStatus::NotProvided
    }

    pub(crate) fn verify_peer_share_index(&self, from: PublicKey, share_index: u16) -> Result<()> {
        let peers = self.peers.read();
        let peer = peers.get_peer(share_index).ok_or_else(|| {
            FrostNetError::UntrustedPeer(format!("Share index {share_index} not announced"))
        })?;
        if peer.pubkey != from {
            return Err(FrostNetError::UntrustedPeer(format!(
                "Sender {from} doesn't match share index {share_index}"
            )));
        }
        Ok(())
    }

    async fn handle_ping(&self, from: PublicKey, payload: PingPayload) -> Result<()> {
        let event = KfpEventBuilder::pong(&self.keys, &from, payload.challenge)?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| FrostNetError::Transport(e.to_string()))?;

        self.peers.write().touch_by_pubkey(&from);

        Ok(())
    }

    async fn handle_pong(&self, from: PublicKey, _payload: PongPayload) -> Result<()> {
        self.peers.write().touch_pong_by_pubkey(&from);
        Ok(())
    }

    pub async fn health_check(&self, timeout: Duration) -> Result<HealthCheckResult> {
        if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(300) {
            return Err(FrostNetError::Session(format!(
                "Health check timeout must be between 1s and 300s, got {}s",
                timeout.as_secs()
            )));
        }
        let peers_snapshot: Vec<(u16, PublicKey, Option<std::time::Instant>)> = self
            .peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.pubkey, p.last_pong))
            .collect();

        let responsive = self
            .ping_peers_snapshot(&peers_snapshot, timeout, None)
            .await?;
        let unresponsive: Vec<u16> = peers_snapshot
            .iter()
            .map(|(idx, _, _)| *idx)
            .filter(|idx| !responsive.contains(idx))
            .collect();

        let result = HealthCheckResult {
            responsive,
            unresponsive,
        };

        let _ = self.event_tx.send(KfpNodeEvent::HealthCheckComplete {
            group_pubkey: self.group_pubkey,
            responsive: result.responsive.clone(),
            unresponsive: result.unresponsive.clone(),
        });

        Ok(result)
    }

    pub async fn ping_peers(&self, timeout: Duration) -> Result<Vec<u16>> {
        let peers_snapshot: Vec<(u16, PublicKey, Option<std::time::Instant>)> = self
            .peers
            .read()
            .all_peers()
            .iter()
            .map(|p| (p.share_index, p.pubkey, p.last_pong))
            .collect();

        self.ping_peers_snapshot(&peers_snapshot, timeout, None)
            .await
    }

    async fn ping_peers_snapshot(
        &self,
        peers_snapshot: &[(u16, PublicKey, Option<std::time::Instant>)],
        timeout: Duration,
        early_exit_at: Option<usize>,
    ) -> Result<Vec<u16>> {
        if peers_snapshot.is_empty() {
            return Ok(Vec::new());
        }

        for (share_index, pubkey, _) in peers_snapshot {
            match KfpEventBuilder::ping(&self.keys, pubkey) {
                Ok(event) => {
                    if let Err(e) = self.client.send_event(&event).await {
                        warn!(
                            peer = %pubkey,
                            share_index,
                            error = %e,
                            "Failed to send ping"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        peer = %pubkey,
                        share_index,
                        error = %e,
                        "Failed to build ping event"
                    );
                }
            }
        }

        // A peer counts as responsive only when a *new* Pong arrived after this
        // snapshot was taken. Comparing `last_pong` against the captured baseline
        // (rather than generic `last_seen`) prevents a peer that merely
        // re-announced, without answering our ping, from being classified live,
        // which is exactly the partial-connectivity case the pre-round ping
        // targets. A peer with no prior pong (`None` baseline) is responsive once
        // it has any `last_pong`.
        let responsive = |snapshot: &[(u16, PublicKey, Option<std::time::Instant>)]| -> Vec<u16> {
            let peers = self.peers.read();
            snapshot
                .iter()
                .filter_map(|(share_index, _, baseline_pong)| {
                    peers
                        .get_peer(*share_index)
                        .filter(|p| match (p.last_pong, baseline_pong) {
                            (Some(current), Some(baseline)) => current > *baseline,
                            (Some(_), None) => true,
                            (None, _) => false,
                        })
                        .map(|_| *share_index)
                })
                .collect()
        };

        // Without an early-exit target, classify every peer after the full
        // timeout (health check). With one, poll and return as soon as that many
        // peers have ponged so the all-online path resolves in roughly one
        // round-trip instead of waiting out the whole timeout.
        let Some(target) = early_exit_at else {
            tokio::time::sleep(timeout).await;
            return Ok(responsive(peers_snapshot));
        };

        let deadline = std::time::Instant::now() + timeout;
        loop {
            let current = responsive(peers_snapshot);
            if current.len() >= target || std::time::Instant::now() >= deadline {
                return Ok(current);
            }
            tokio::time::sleep(LIVENESS_PING_POLL_INTERVAL).await;
        }
    }
}

fn default_relay_opts() -> RelayOptions {
    RelayOptions::default()
        .reconnect(true)
        .ping(true)
        .retry_interval(Duration::from_secs(10))
        .adjust_retry_interval(true)
        .ban_relay_on_mismatch(true)
        .max_avg_latency(Some(Duration::from_secs(3)))
}

/// Derives a member's transport keypair from public group data. The derivation
/// is deterministic in `(group_pubkey, identifier)`, both public, so every
/// member can compute every other member's transport pubkey without discovery.
/// This is what lets the relay subscriptions filter by `authors`.
fn derive_member_keys(group_pubkey: &[u8; 32], identifier: u16) -> Result<Keys> {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-node-identity-v2");
    hasher.update(group_pubkey);
    hasher.update(identifier.to_be_bytes());
    let derived: [u8; 32] = hasher.finalize().into();
    let secret_key = SecretKey::from_slice(&derived)
        .map_err(|e| FrostNetError::Crypto(format!("Failed to create secret key: {e}")))?;
    Ok(Keys::new(secret_key))
}

fn derive_keys_from_share(share: &SharePackage) -> Result<Keys> {
    derive_member_keys(&share.metadata.group_pubkey, share.metadata.identifier)
}

/// Transport pubkeys of every member of the group, derived from public data.
/// Used to scope relay subscriptions to `authors`, which keeps strict relays
/// happy (they require `authors`/`#p`) and avoids pulling the relay's entire
/// `kind:24242` stream (shared with Blossom and other groups).
fn group_member_pubkeys(group_pubkey: &[u8; 32], total_shares: u16) -> Vec<PublicKey> {
    (1..=total_shares)
        .filter_map(|i| {
            derive_member_keys(group_pubkey, i)
                .ok()
                .map(|k| k.public_key())
        })
        .collect()
}

fn derive_audit_hmac_key(keys: &Keys, group_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-audit-hmac-v1");
    hasher.update(keys.secret_key().secret_bytes());
    hasher.update(group_pubkey);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::frost::{ThresholdConfig, TrustedDealer};
    use nostr_relay_builder::MockRelay;

    #[tokio::test]
    async fn test_node_creation() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await.to_string();

        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (mut shares, _) = dealer.generate("test").unwrap();

        let share = shares.remove(0);
        let result = KfpNode::new(share, vec![relay_url]).await;
        assert!(result.is_ok());

        let node = result.unwrap();
        assert_eq!(node.share_index(), 1);
    }

    #[tokio::test]
    async fn serve_hooks_oprf_auto_approve_opt_in() {
        let approving = ServeHooks {
            refuse_raw_sign: false,
            require_structured_payload: false,
            auto_approve_oprf_eval: true,
        };
        assert!(approving.approve_oprf_eval(2, [0u8; 32]).await);

        let declining = ServeHooks {
            refuse_raw_sign: false,
            require_structured_payload: false,
            auto_approve_oprf_eval: false,
        };
        assert!(!declining.approve_oprf_eval(2, [0u8; 32]).await);
    }

    #[test]
    fn serve_hooks_refuse_raw_sign_gates_pre_sign() {
        let hooks = ServeHooks {
            refuse_raw_sign: true,
            require_structured_payload: false,
            auto_approve_oprf_eval: false,
        };

        let raw = raw_session();
        assert!(
            hooks.pre_sign(&raw).is_err(),
            "refuse_raw_sign must reject message_type=\"raw\""
        );

        let mut structured = raw_session();
        structured.message_type = "nostr-event".to_string();
        hooks
            .pre_sign(&structured)
            .expect("non-raw session must pass pre_sign");
    }

    fn descriptor_version(
        group: [u8; 32],
        external: &str,
        version: u32,
    ) -> keep_core::wallet::WalletDescriptor {
        keep_core::wallet::WalletDescriptor {
            group_pubkey: group,
            external_descriptor: external.to_string(),
            internal_descriptor: String::new(),
            network: "regtest".to_string(),
            created_at: 0,
            device_registrations: Vec::new(),
            policy_hash: [0u8; 32],
            version,
            previous_descriptor_hash: None,
            policy: None,
        }
    }

    #[test]
    fn external_for_resolves_superseded_version() {
        let group = [3u8; 32];
        let old = descriptor_version(group, "tr(old_external)", 1);
        let new = descriptor_version(group, "tr(new_external)", 2);
        let old_hash = old.canonical_hash();
        let new_hash = new.canonical_hash();
        assert_ne!(old_hash, new_hash);

        let rows = vec![old.clone(), new.clone()];
        let lookup = KeepDescriptorLookup::new(move || Some(rows.clone()));

        assert_eq!(
            lookup.external_for(&group, &old_hash).as_deref(),
            Some("tr(old_external)"),
            "migration sweep must resolve the superseded OLD descriptor across all versions",
        );
        assert_eq!(
            lookup.external_for(&group, &new_hash).as_deref(),
            Some("tr(new_external)"),
        );
        assert_eq!(lookup.latest_version_for(&group), Ok(Some(2)));
        assert!(lookup.find_by_hash(&group, &old_hash));
        assert!(lookup.find_by_hash(&group, &new_hash));
    }

    #[test]
    fn successor_for_returns_new_descriptor_keyed_on_old_hash() {
        // #414: responders need to re-derive the expected sweep destination
        // from the NEW descriptor whose `previous_descriptor_hash` is the
        // session's OLD descriptor hash. Confirm the lookup walks the
        // back-pointer chain correctly.
        let group = [7u8; 32];
        let old = descriptor_version(group, "tr(old_external)", 1);
        let old_hash = old.canonical_hash();

        let mut new = descriptor_version(group, "tr(new_external)", 2);
        new.previous_descriptor_hash = Some(old_hash);

        let rows = vec![old.clone(), new.clone()];
        let lookup = KeepDescriptorLookup::new(move || Some(rows.clone()));

        match lookup.successor_for(&group, &old_hash) {
            SuccessorLookup::Found {
                external_descriptor,
                ..
            } => assert_eq!(external_descriptor, "tr(new_external)"),
            other => panic!("expected Found, got {other:?}"),
        }
        // The NEW descriptor itself is the tip; there is no successor.
        let new_hash = new.canonical_hash();
        assert_eq!(
            lookup.successor_for(&group, &new_hash),
            SuccessorLookup::Tip
        );
        // Wrong group never matches.
        assert_eq!(
            lookup.successor_for(&[8u8; 32], &old_hash),
            SuccessorLookup::Tip,
            "successor lookup must be scoped to the queried group",
        );
    }

    #[test]
    fn successor_for_returns_tip_without_chain() {
        // The current-tip descriptor has no successor; responders signing
        // against the tip should NOT be subjected to the migration check.
        let group = [11u8; 32];
        let tip = descriptor_version(group, "tr(tip)", 1);
        let tip_hash = tip.canonical_hash();
        let rows = vec![tip.clone()];
        let lookup = KeepDescriptorLookup::new(move || Some(rows.clone()));
        assert_eq!(
            lookup.successor_for(&group, &tip_hash),
            SuccessorLookup::Tip
        );
    }

    #[test]
    fn successor_for_fails_closed_when_store_unavailable() {
        // A locked/poisoned vault must surface Unavailable so the responder
        // fails closed instead of silently skipping the destination check.
        let group = [12u8; 32];
        let hash = [3u8; 32];
        let lookup = KeepDescriptorLookup::new(move || None);
        assert_eq!(
            lookup.successor_for(&group, &hash),
            SuccessorLookup::Unavailable
        );
    }

    #[test]
    fn successor_for_picks_version_plus_one_when_multiple_back_point() {
        // Two descriptors back-point to the same OLD hash. The deterministic
        // session+1 successor is selected rather than relying on Vec order.
        let group = [13u8; 32];
        let old = descriptor_version(group, "tr(old)", 1);
        let old_hash = old.canonical_hash();

        let mut next = descriptor_version(group, "tr(next)", 2);
        next.previous_descriptor_hash = Some(old_hash);
        let mut stray = descriptor_version(group, "tr(stray)", 3);
        stray.previous_descriptor_hash = Some(old_hash);

        // stray listed first to prove order independence.
        let rows = vec![old.clone(), stray.clone(), next.clone()];
        let lookup = KeepDescriptorLookup::new(move || Some(rows.clone()));
        match lookup.successor_for(&group, &old_hash) {
            SuccessorLookup::Found {
                external_descriptor,
                ..
            } => assert_eq!(external_descriptor, "tr(next)"),
            other => panic!("expected Found(next), got {other:?}"),
        }
    }

    #[test]
    fn successor_for_ambiguous_when_no_single_version_plus_one() {
        // Two successors at the same version with no version+1 match is a
        // genuinely ambiguous lineage; fail closed.
        let group = [14u8; 32];
        let old = descriptor_version(group, "tr(old)", 1);
        let old_hash = old.canonical_hash();

        let mut a = descriptor_version(group, "tr(a)", 5);
        a.previous_descriptor_hash = Some(old_hash);
        let mut b = descriptor_version(group, "tr(b)", 6);
        b.previous_descriptor_hash = Some(old_hash);

        let rows = vec![old.clone(), a.clone(), b.clone()];
        let lookup = KeepDescriptorLookup::new(move || Some(rows.clone()));
        assert_eq!(
            lookup.successor_for(&group, &old_hash),
            SuccessorLookup::Ambiguous
        );
    }

    fn raw_session() -> SessionInfo {
        SessionInfo {
            session_id: [7u8; 32],
            message: vec![0u8; 32],
            threshold: 2,
            participants: vec![1, 2],
            requester: 1,
            message_type: "raw".to_string(),
            structured_payload: None,
        }
    }

    /// Build a nostr-event `SessionInfo` for hook tests: 32-byte digest,
    /// canonical label, with or without a structured payload.
    fn nostr_session(structured: Option<Vec<u8>>) -> SessionInfo {
        SessionInfo {
            session_id: [8u8; 32],
            message: vec![0u8; 32],
            threshold: 2,
            participants: vec![1, 2],
            requester: 1,
            message_type: crate::MSG_TYPE_NOSTR_EVENT.to_string(),
            structured_payload: structured,
        }
    }

    /// #529: `RequireStructuredPayloadHooks` refuses any request whose
    /// `structured_payload` is None, so a caller relabeling a raw digest as
    /// "nostr-event" without providing a body is rejected before the
    /// signing round begins.
    #[test]
    fn require_structured_payload_refuses_when_absent() {
        let session = nostr_session(None);
        let err = crate::RequireStructuredPayloadHooks
            .pre_sign(&session)
            .expect_err("absent structured payload must be refused");
        assert!(matches!(err, FrostNetError::PolicyViolation(_)));
    }

    /// #529: `RequireStructuredPayloadHooks` accepts requests whose
    /// structured payload is present; recompute-vs-digest matching is
    /// enforced by the built-in pre-sign check in the signing loop, not by
    /// this hook.
    #[test]
    fn require_structured_payload_accepts_when_present() {
        let session = nostr_session(Some(vec![1, 2, 3]));
        crate::RequireStructuredPayloadHooks
            .pre_sign(&session)
            .expect("presence-only check must accept when payload is attached");
    }

    /// #529: `RefuseRawAndRequireStructuredHooks` composes the two rules
    /// operators of hybrid groups need: `"raw"` labels are still refused,
    /// and every other label must attach a structured body.
    #[test]
    fn refuse_raw_and_require_structured_composes_both_rules() {
        let hooks = crate::RefuseRawAndRequireStructuredHooks;
        assert!(hooks.pre_sign(&raw_session()).is_err());
        assert!(hooks.pre_sign(&nostr_session(None)).is_err());
        hooks
            .pre_sign(&nostr_session(Some(vec![0u8; 4])))
            .expect("structured nostr-event is accepted");
    }

    #[test]
    fn refuse_raw_signature_hooks_rejects_raw_label() {
        let hooks = RefuseRawSignatureHooks;
        let session = raw_session();
        let err = hooks
            .pre_sign(&session)
            .expect_err("raw label must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("refuses message_type=\"raw\""),
            "error must explain why: {msg}"
        );
        assert!(msg.contains(&hex::encode(session.session_id)));
    }

    #[test]
    fn refuse_raw_signature_hooks_rejects_raw_label_variants() {
        // Case- and whitespace-insensitive: the honest raw paths emit lowercase
        // "raw", but a careless relabel like " RAW\n" must not slip through.
        let hooks = RefuseRawSignatureHooks;
        for label in ["RAW", "Raw", " raw", "raw\n", "\traw "] {
            let mut session = raw_session();
            session.message_type = label.to_string();
            assert!(
                hooks.pre_sign(&session).is_err(),
                "variant {label:?} must be refused"
            );
        }
    }

    #[test]
    fn refuse_raw_signature_hooks_accepts_other_labels() {
        let hooks = RefuseRawSignatureHooks;
        for label in ["nostr-event", "bitcoin-sighash", "psbt-input-0", ""] {
            let mut session = raw_session();
            session.message_type = label.to_string();
            hooks
                .pre_sign(&session)
                .unwrap_or_else(|e| panic!("label {label:?} must be allowed, got {e}"));
        }
    }

    #[test]
    fn noop_hooks_accepts_raw() {
        // NoOpHooks preserves the original behavior: no domain gating. Pin
        // this so callers know that switching from NoOpHooks to
        // RefuseRawSignatureHooks is the only behavioral change.
        let hooks = NoOpHooks;
        let session = raw_session();
        hooks.pre_sign(&session).unwrap();
    }
}
