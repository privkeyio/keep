// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod approver;
mod audit;
mod dkg;
mod error;
mod network;
mod nip46;
mod nip46_ratelimit;
mod nip55;
mod nip55_audit;
mod nip55_caller;
mod nip55_decision;
mod nip55_policy;
mod nip55_ratelimit;
mod persistence;
mod policy;
mod psbt;
mod signing_policy;
mod storage;
mod storage_integrity;
mod types;
mod velocity;

pub use approver::{
    ApprovalField, ApprovalRequest, ApproverCallbacks, ApproverEvent, ApproverHandler,
    ApproverStatus, PairingStart,
};
pub use audit::{
    AuditEntry, AuditEventType, AuditLog, AuditStorage, SigningAuditEntry, SigningAuditLog,
    SigningAuditStorage, SigningDecision, SigningRequestType,
};
pub use dkg::{DkgProgressCallback, DkgResult};
pub use error::KeepMobileError;
pub use nip46::{
    parse_bunker_url, BunkerApprovalRequest, BunkerCallbacks, BunkerHandler, BunkerLogEvent,
    BunkerStatus, ParsedBunkerUrl,
};
pub use nip55::{Nip55Handler, Nip55Request, Nip55RequestType, Nip55Response};
pub use nip55_decision::{
    evaluate_nip55_request, nip55_needs_biometric, Nip55DecisionInputs, Nip55Outcome,
    Nip55VelocityCheck,
};
pub use policy::{PolicyDecision, PolicyFault, PolicyInfo, PolicyStatus, TransactionContext};
pub use psbt::{PsbtInfo, PsbtInputSighash, PsbtOutputInfo, PsbtParser};
pub use signing_policy::{
    assess_signing_risk, evaluate_sign_policy, evaluate_sign_policy_selection, is_sensitive_kind,
    sensitive_kind_warning, AutoSignDecision, PolicyMode, SignPolicyEvaluation,
    SignPolicySelection, SigningAuthLevel, SigningRateLimiter, SigningRequestContext,
    SigningRiskAssessment, SigningRiskFactor, UsageStats,
};
pub use storage::{PendingShareInfo, SecureStorage, ShareInfo, ShareMetadataInfo, StoredShareInfo};
pub use types::{
    AnnouncedXpubInfo, BackupInfo, ConnectionStatus, DescriptorProposal, DeviceRegistrationInfo,
    DkgConfig, DkgParticipant, DkgProgressUpdate, FrostGenerationResult, GeneratedShareInfo,
    KeepLiveState, KeyHealthStatusInfo, PeerInfo, PeerStatus, RecoveryTierConfig,
    RosterVerification, SignRequest, SignRequestMetadata, ThresholdConfig, WalletDescriptorInfo,
};

#[uniffi::export]
pub fn format_timestamp(ts: i64) -> String {
    keep_core::display::format_timestamp(ts)
}

#[uniffi::export]
pub fn format_timestamp_detailed(ts: i64) -> String {
    keep_core::display::format_timestamp_detailed(ts)
}

#[uniffi::export]
pub fn truncate_str(s: String, prefix_len: u32, suffix_len: u32) -> String {
    keep_core::display::truncate_str(&s, prefix_len as usize, suffix_len as usize)
}

#[uniffi::export]
pub fn is_hex_64(value: String) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Assemble the coordinator's DKG roster in Rust: index 1 is the coordinator,
/// each collected joiner subkey takes index i+2 in scan order (§4). Rejects a
/// malformed or duplicated subkey before it reaches the wire. The roster-assembly
/// policy lives here, not in the setup UI, so there is one authority on how
/// indices map to keys.
#[uniffi::export]
pub fn frost_assemble_roster(
    coordinator_pubkey: String,
    joiner_pubkeys: Vec<String>,
) -> Result<Vec<DkgParticipant>, KeepMobileError> {
    dkg::assemble_roster(&coordinator_pubkey, &joiner_pubkeys)
}

/// Validate a finalized roster with the same checks `frost_run_dkg` applies
/// (index range/uniqueness, duplicate-pubkey rejection, threshold/participant
/// bounds), resolve this device's index by matching `our_pubkey`, and return a
/// human-comparable fingerprint of the canonical `frost_group_id`. The setup UI
/// renders this fingerprint instead of recomputing its own digest, so the value
/// read aloud out of band cannot drift from the id the run actually uses.
#[uniffi::export]
pub fn frost_verify_roster(
    group_name: String,
    threshold: u16,
    participants: u16,
    roster: Vec<DkgParticipant>,
    our_pubkey: String,
) -> Result<RosterVerification, KeepMobileError> {
    dkg::verify_roster(&group_name, threshold, participants, &roster, &our_pubkey)
}

#[uniffi::export]
pub fn hex_to_npub(hex: String) -> Option<String> {
    use nostr_sdk::prelude::{PublicKey, ToBech32};
    PublicKey::from_hex(&hex)
        .ok()
        .and_then(|pk| pk.to_bech32().ok())
}

#[uniffi::export]
pub fn format_pubkey_display(pubkey: String) -> String {
    let bech32 = hex_to_npub(pubkey.clone()).unwrap_or(pubkey);
    keep_core::display::truncate_str(&bech32, 12, 8)
}

#[uniffi::export]
pub fn format_event_id_display(event_id: String, relay_url: Option<String>) -> String {
    use nostr_sdk::prelude::{EventId, Nip19Event, RelayUrl, ToBech32};
    let nevent = EventId::from_hex(&event_id).ok().and_then(|id| {
        let mut ev = Nip19Event::new(id);
        if let Some(url) = relay_url.and_then(|r| RelayUrl::parse(&r).ok()) {
            ev = ev.relays(vec![url]);
        }
        ev.to_bech32().ok()
    });
    let display = nevent.unwrap_or(event_id);
    keep_core::display::truncate_str(&display, 12, 8)
}

#[uniffi::export]
pub fn is_valid_nsec_format(nsec: String) -> bool {
    use nostr_sdk::prelude::{FromBech32, SecretKey};
    SecretKey::from_bech32(&nsec).is_ok()
}

#[uniffi::export]
pub fn backup_min_passphrase_length() -> u32 {
    keep_core::backup::MIN_PASSPHRASE_LEN as u32
}

#[uniffi::export]
pub fn nip55_max_batch_size() -> u32 {
    nip55::MAX_BATCH_SIZE as u32
}

#[uniffi::export]
pub fn recover_nsec(
    share_data: Vec<String>,
    passphrases: Vec<String>,
    expected_group_pubkey: Option<Vec<u8>>,
) -> Result<String, KeepMobileError> {
    use zeroize::Zeroize;

    let group_pk = expected_group_pubkey
        .as_ref()
        .map(|v| {
            <[u8; 32]>::try_from(v.as_slice()).map_err(|_| KeepMobileError::InvalidInput {
                msg: "expected_group_pubkey must be 32 bytes".into(),
            })
        })
        .transpose()?;

    let result = keep_core::frost::recover_nsec(&share_data, &passphrases, group_pk.as_ref());

    let mut share_data = share_data;
    let mut passphrases = passphrases;
    for s in &mut share_data {
        s.zeroize();
    }
    for p in &mut passphrases {
        p.zeroize();
    }

    result
        .map(|z| z.to_string())
        .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
}

#[uniffi::export]
pub fn is_valid_bech32_char(c: String) -> bool {
    const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    c.len() == 1
        && c.chars()
            .next()
            .is_some_and(|ch| BECH32_CHARSET.contains(ch))
}

#[uniffi::export]
pub fn generate_animated_frames(
    bech32_data: String,
    max_bytes: u32,
) -> Result<Vec<String>, KeepMobileError> {
    let export = keep_core::frost::ShareExport::from_bech32(&bech32_data)
        .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;
    let max = (max_bytes as usize).max(50);
    export
        .to_animated_frames(max)
        .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })
}

#[uniffi::export]
pub fn reassemble_animated_frames(frames: Vec<String>) -> Result<String, KeepMobileError> {
    let export = keep_core::frost::ShareExport::from_animated_frames(&frames)
        .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;
    export
        .to_bech32()
        .or_else(|e| {
            tracing::warn!("bech32 encoding failed, falling back to JSON: {e}");
            export.to_json()
        })
        .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })
}

use keep_core::frost::{
    ShareExport, ShareMetadata, SharePackage, ThresholdConfig as CoreThresholdConfig, TrustedDealer,
};
use keep_frost_net::{KfpNode, KfpNodeEvent, SessionInfo, SigningHooks};
use network::{constant_time_eq, convert_peer_status, parse_loopback_proxy, validate_hex_pubkey};
use policy::{PolicyBundle, PolicyEvaluator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use velocity::VelocityTracker;
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

fn init_logging() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        #[cfg(target_os = "android")]
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("KeepRust").unwrap())
            .try_init();

        #[cfg(not(target_os = "android"))]
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .try_init();
    });
}

/// Builds the approval-facing request from a coordination session.
///
/// The label is carried across so the prompt is not an unlabelled hash. Whether
/// it can be trusted depends entirely on [`SignRequest::type_verified`], and the
/// two cases must not be conflated.
///
/// When that flag is false the label is **requester-supplied and not bound to
/// the signed bytes**, so a peer can relabel a sighash as anything it likes. It
/// is then a hint about what the requester claims, never proof of what the bytes
/// are, and nothing may treat it as the domain discriminator. That is the common
/// case today, because the hooks that would require a structured body do not run
/// here: installing hooks replaces the set rather than composing with it, so this
/// crate's hooks are the only pre-sign policy on mobile.
///
/// When it is true the label was proven against the signed bytes, and it is one
/// of exactly two known constants. What that proves is narrow and worth stating
/// so surfaces do not overclaim: it establishes the *domain* of the bytes, not
/// their contents. A verified Bitcoin sighash means these bytes really are a
/// taproot key-spend sighash for the supplied transaction. It does not mean the
/// transaction spends what the user expects, to whom they expect, or that the
/// prevout scripts belong to this group. Wording that reads as a blanket
/// "verified" would claim far more than was checked.
///
/// Because it reaches a prompt and a notification, it goes through the same
/// sanitizer every other adversary-authored prompt field in this codebase uses,
/// which strips control characters and bidi overrides and caps the length. A
/// newline here would otherwise render as extra lines in the notification body,
/// and a right-to-left override would let the requester rewrite the text around
/// it.
///
/// The requester index is authenticated: it is resolved from the signature-
/// verified sender rather than taken from the payload, so a peer cannot claim
/// another peer's index.
///
/// `metadata` stays empty. Its fields come from the session's structured
/// payload, which needs decoding per message type before it can be trusted to
/// populate an amount or a destination, and showing a wrong amount would be
/// worse than showing none.
fn sign_request_from_session(session: &keep_frost_net::SessionInfo) -> SignRequest {
    SignRequest {
        id: hex::encode(session.session_id),
        session_id: session.session_id.to_vec(),
        message_type: keep_nip46::handler::sanitize_prompt_field(
            &session.message_type,
            MESSAGE_TYPE_DISPLAY_MAX,
        ),
        // A structured body present here has already been checked: the responder
        // recomputes the digest that body produces and refuses the request when
        // it does not equal the bytes being signed, before this hook runs. An
        // unknown label with a body attached is refused outright. So a payload
        // surviving to this point means the label matches the content, and its
        // absence means nothing verified it.
        type_verified: session.structured_payload.is_some(),
        message_preview: hex::encode(&session.message[..session.message.len().min(8)]),
        from_peer: session.requester,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        metadata: None,
    }
}

/// Display cap for the requester-supplied label, matching the method-name cap
/// used for the other short prompt field in this codebase. The wire validator
/// already bounds it, but that bound lives in another crate and does not apply
/// to a session built by any other route.
const MESSAGE_TYPE_DISPLAY_MAX: usize = 32;

const MAX_PENDING_REQUESTS: usize = 100;
const SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_IMPORT_DATA_SIZE: usize = 64 * 1024;
const MAX_STORED_SHARES: usize = 100;
const MAX_PRE_APPROVED_HASHES: usize = 100;
const PRE_APPROVAL_TTL: Duration = Duration::from_secs(300);
const MAX_SHARE_NAME_LENGTH: usize = 64;

type PreApprovedHashes =
    Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], std::time::Instant>>>;

fn lock_pre_approved(
    hashes: &PreApprovedHashes,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<[u8; 32], std::time::Instant>> {
    let now = std::time::Instant::now();
    let mut guard = hashes.lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|_, &mut inserted| now.duration_since(inserted) < PRE_APPROVAL_TTL);
    guard
}

const POLICY_STORAGE_KEY: &str = "__keep_policy_v1";
const VELOCITY_STORAGE_KEY: &str = "__keep_velocity_v1";
const TRUSTED_WARDENS_KEY: &str = "__keep_trusted_wardens_v1";
const CERT_PINS_STORAGE_KEY: &str = "__keep_cert_pins_v1";
const DESCRIPTOR_INDEX_KEY: &str = "__keep_descriptor_index_v1";
const DESCRIPTOR_KEY_PREFIX: &str = "__keep_descriptor_";
const HEALTH_STATUS_INDEX_KEY: &str = "__keep_health_index_v1";
const HEALTH_STATUS_KEY_PREFIX: &str = "__keep_health_";
const RELAY_CONFIG_KEY_PREFIX: &str = "__keep_relay_config_";
const RELAY_CONFIG_GLOBAL_KEY: &str = "__keep_relay_config_global";
const PROXY_CONFIG_STORAGE_KEY: &str = "__keep_proxy_config_v1";
const STRICT_PIN_CONFIG_STORAGE_KEY: &str = "__keep_strict_pin_config_v1";
const BUNKER_CONFIG_STORAGE_KEY: &str = "__keep_bunker_config_v1";
const KILL_SWITCH_STORAGE_KEY: &str = "__keep_kill_switch_v1";
/// Non-sensitive pending-DKG marker (name/group/protection). Under the `__keep_`
/// metadata namespace so it reads without a vault unlock.
const DKG_PENDING_MARKER_KEY: &str = "__keep_dkg_pending_v1";
/// Sensitive pending-DKG secret (share export + ephemeral passphrase). The
/// platform routes this reserved key to a dedicated auth-gated (`requireUserAuth`)
/// alias, so it is not app-uid-readable at rest and loading it costs a vault unlock.
const DKG_PENDING_SECRET_KEY: &str = "__keep_dkg_secret_v1";
const DESCRIPTOR_SESSION_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(uniffi::Record)]
pub struct CertificatePin {
    pub hostname: String,
    pub spki_hash: String,
}

#[derive(uniffi::Record)]
pub struct CertPinRemovalResult {
    /// Whether a pin was actually removed (false when the hash was not present).
    pub pin_removed: bool,
    /// Whether the host now has no pins left. The next connection will
    /// trust-on-first-use and re-pin whatever cert is presented, so the UI should
    /// require explicit confirmation before leaving a host unpinned.
    pub host_now_unpinned: bool,
}

#[derive(uniffi::Record)]
pub struct RelayConfigInfo {
    pub frost_relays: Vec<String>,
    pub profile_relays: Vec<String>,
    pub bunker_relays: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct ProxyConfigInfo {
    pub enabled: bool,
    pub port: u16,
}

#[derive(uniffi::Record)]
pub struct BunkerConfigInfo {
    pub enabled: bool,
    pub authorized_clients: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredShareData {
    metadata_json: String,
    key_package_bytes: Zeroizing<Vec<u8>>,
    pubkey_package_bytes: Vec<u8>,
    // Relies on SecureStorage (Android Keystore / iOS Keychain) for encryption at rest
    #[serde(default)]
    plaintext_mnemonic: Option<Zeroizing<Vec<u8>>>,
    // Defaults to Secp256k1Tr so shares written before this field existed parse unchanged.
    #[serde(default)]
    ciphersuite: keep_core::frost::Ciphersuite,
}

#[uniffi::export(with_foreign)]
pub trait HealthCallbacks: Send + Sync {
    fn on_health_check_complete(
        &self,
        responsive: Vec<u16>,
        unresponsive: Vec<u16>,
    ) -> Result<(), KeepMobileError>;
}

#[uniffi::export(with_foreign)]
pub trait DescriptorCallbacks: Send + Sync {
    fn on_proposed(&self, session_id: String) -> Result<(), KeepMobileError>;
    fn on_contribution_needed(&self, proposal: DescriptorProposal) -> Result<(), KeepMobileError>;
    fn on_contributed(&self, session_id: String, share_index: u16) -> Result<(), KeepMobileError>;
    fn on_complete(
        &self,
        session_id: String,
        external_descriptor: String,
        internal_descriptor: String,
    ) -> Result<(), KeepMobileError>;
    fn on_failed(&self, session_id: String, error: String) -> Result<(), KeepMobileError>;
    fn on_xpub_announced(
        &self,
        share_index: u16,
        xpubs: Vec<AnnouncedXpubInfo>,
    ) -> Result<(), KeepMobileError>;
}

#[uniffi::export(with_foreign)]
pub trait KeepStateCallback: Send + Sync + 'static {
    fn on_state_changed(&self, state: KeepLiveState) -> Result<(), KeepMobileError>;
}

struct MobileSigningHooks {
    request_tx: mpsc::Sender<(SessionInfo, mpsc::Sender<bool>)>,
    pre_approved_hashes: PreApprovedHashes,
    /// Read on every round so the kill switch ("Signing Disabled") gates FROST
    /// co-signing too, not just the NIP-55/NIP-46 paths.
    storage: Arc<dyn SecureStorage>,
}

impl MobileSigningHooks {
    fn consume_pre_approval(&self, message: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let msg_hash: [u8; 32] = Sha256::digest(message).into();
        lock_pre_approved(&self.pre_approved_hashes)
            .remove(&msg_hash)
            .is_some()
    }
}

impl SigningHooks for MobileSigningHooks {
    fn pre_sign(&self, session: &SessionInfo) -> keep_frost_net::Result<()> {
        // Kill switch: when co-signing is disabled, refuse to take part in any
        // signing round, including pre-approved requests, without prompting.
        // Fail-closed (an unreadable switch is treated as engaged), mirroring
        // keep-web's bunker.
        if persistence::load_kill_switch(&self.storage, KILL_SWITCH_STORAGE_KEY).unwrap_or(true) {
            return Err(keep_frost_net::FrostNetError::PolicyViolation(
                "co-signing is disabled".into(),
            ));
        }
        // Baseline pre-sign policy. Installing hooks replaces the set rather
        // than composing with it, so the policies that refuse an unstructured
        // request never run on this crate's node unless it invokes them
        // itself. Without this, a phone co-signer accepts message_type="raw":
        // 32 bytes with no claimed domain at all, which frost-secp256k1 signs
        // verbatim and which is therefore indistinguishable from a Bitcoin
        // sighash once signed.
        //
        // Placed before the pre-approval short-circuit for the same reason the
        // kill switch is: an approval recorded earlier must not authorise a
        // request the policy refuses now. Putting it after would let exactly
        // the requests that skip the prompt also skip the policy.
        //
        // Requiring a structured body on every request is the stronger policy
        // and is deliberately not applied here: the payload is optional at the
        // request site, so making it mandatory would refuse initiators that do
        // not attach one, and a co-signer that cannot sign reads as broken
        // rather than as protected.
        //
        // The CLI's `frost network sign` does send the raw label, so this is
        // not a label nothing produces. A refusal there is not fatal: the
        // coordinator excludes the index and fails over, and only errors when
        // this share is needed to reach threshold. A phone holding key material
        // is the right place to be stricter than the default serve policy.
        keep_frost_net::RefuseRawSignatureHooks.pre_sign(session)?;

        // Refuse anything whose *displayed* label is blank or raw, normalising
        // exactly the way the prompt does before deciding.
        //
        // Two gaps close here, and both come from the check and the display
        // disagreeing about what a label says. The policy above compares the
        // untouched string, while the prompt strips zero-width characters, so
        // a label of "raw\u{200b}" is not refused and still renders as "raw".
        // And an empty label defeats a denylist outright while rendering worse
        // than the label it evades: the surface drops a blank label entirely,
        // taking the "claimed:" qualifier with it, so the request carrying no
        // stated domain at all would show fewer warnings than one that says
        // "raw". The most dangerous request must not be the least alarming.
        let shown = keep_nip46::handler::sanitize_prompt_field(
            &session.message_type,
            MESSAGE_TYPE_DISPLAY_MAX,
        );
        let shown = shown.trim();
        if shown.is_empty() || shown.eq_ignore_ascii_case(keep_frost_net::MSG_TYPE_RAW) {
            return Err(keep_frost_net::FrostNetError::PolicyViolation(format!(
                "co-signer refuses a request whose label displays as {}: \
                 an approval prompt cannot describe what it is asking about. \
                 session_id={}, requester=share {}",
                if shown.is_empty() { "blank" } else { "raw" },
                hex::encode(session.session_id),
                session.requester
            )));
        }

        if self.consume_pre_approval(&session.message) {
            return Ok(());
        }

        let (response_tx, mut response_rx) = mpsc::channel(1);

        // The interactive approval path runs inside the node's async message
        // handler, so a current runtime is present. We must neither block a
        // worker thread (blocking_send) nor start a nested runtime
        // (Runtime::block_on panics inside a runtime). Use block_in_place to move
        // off the worker, then drive the send + wait on the current handle.
        // INVARIANT: block_in_place panics on a current-thread runtime; the node
        // task runs on the `new_multi_thread()` runtime built in `KeepMobile::new`
        // (below), which satisfies this. Outside a runtime (no current handle),
        // fall back to a blocking send and an owned current-thread runtime.
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let request_tx = self.request_tx.clone();
                let session = session.clone();
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        request_tx.send((session, response_tx)).await.map_err(|_| {
                            keep_frost_net::FrostNetError::Session("Channel closed".into())
                        })?;
                        Ok::<_, keep_frost_net::FrostNetError>(
                            tokio::time::timeout(SIGNING_RESPONSE_TIMEOUT, response_rx.recv())
                                .await,
                        )
                    })
                })?
            }
            Err(_) => {
                if self
                    .request_tx
                    .blocking_send((session.clone(), response_tx))
                    .is_err()
                {
                    return Err(keep_frost_net::FrostNetError::Session(
                        "Channel closed".into(),
                    ));
                }
                let owned_rt = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .map_err(|_| keep_frost_net::FrostNetError::Session("No runtime".into()))?;
                owned_rt.block_on(async {
                    tokio::time::timeout(SIGNING_RESPONSE_TIMEOUT, response_rx.recv()).await
                })
            }
        };

        match result {
            Ok(Some(true)) => Ok(()),
            Ok(Some(false)) => Err(keep_frost_net::FrostNetError::Session(
                "Request rejected".into(),
            )),
            Ok(None) => Err(keep_frost_net::FrostNetError::Session("No response".into())),
            Err(_) => Err(keep_frost_net::FrostNetError::Session("Timeout".into())),
        }
    }

    fn post_sign(&self, _session: &SessionInfo, _signature: &[u8; 64]) {}
}

/// Identity of the single in-flight `frost_run_dkg`: its run id and the cancel
/// flag the coordinator polls. Registered in `KeepMobile::dkg_active` for the
/// run's lifetime so `frost_cancel_dkg` can target it by id.
struct DkgActiveRun {
    id: u64,
    cancel: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(uniffi::Object)]
pub struct KeepMobile {
    pub(crate) node: Arc<RwLock<Option<Arc<KfpNode>>>>,
    /// Handles for the node's spawned run + event-listener tasks. Nulling the
    /// `node` Arc alone does not stop them: each task holds its own Arc clone,
    /// so the node never drops and keeps signing on the relays. Held here so
    /// invalidate_live_node can abort them.
    node_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    pub(crate) storage: Arc<dyn SecureStorage>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    /// Per-group DKG signing subkey secrets minted by `frost_dkg_begin` and held
    /// in memory (never crossing the Kotlin boundary, §8) until `frost_run_dkg`
    /// consumes them. Keyed by group name. Retained after a run so the subkey
    /// stays available with the share (C1); a process restart mid-ceremony just
    /// re-runs `frost_dkg_begin`.
    dkg_subkeys: Arc<std::sync::Mutex<HashMap<String, Zeroizing<[u8; 32]>>>>,
    /// Identity + cancel flag for the single in-flight `frost_run_dkg`. Each run
    /// mints a fresh id (from `dkg_run_seq`) and its own cancel flag, registered
    /// here for its lifetime and cleared on every exit path by `DkgInFlightGuard`.
    /// `frost_cancel_dkg(run_id)` flips the flag only when `run_id` matches the
    /// active run, so a cancel issued for a run that has since finished cannot
    /// abort the next run (§8: no wiping a concurrent run).
    dkg_active: Arc<std::sync::Mutex<Option<DkgActiveRun>>>,
    /// Monotonic allocator for `dkg_active` run ids; the run id also reaches the
    /// UI via `DkgProgressUpdate::Started` so it can target its cancel.
    dkg_run_seq: Arc<std::sync::atomic::AtomicU64>,
    /// Single-flight guard: `frost_run_dkg` shares `dkg_active`/`dkg_subkeys`, so
    /// a second concurrent run would clobber the first's identity. Rejected while
    /// set; cleared on every exit path by `DkgInFlightGuard`.
    dkg_in_flight: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) runtime: tokio::runtime::Runtime,
    policy: Arc<std::sync::RwLock<PolicyEvaluator>>,
    velocity: Arc<std::sync::Mutex<Option<VelocityTracker>>>,
    descriptor_callbacks: Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
    health_callbacks: Arc<RwLock<Option<Arc<dyn HealthCallbacks>>>>,
    descriptor_networks: Arc<std::sync::Mutex<HashMap<[u8; 32], String>>>,
    pending_contributions: Arc<std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>>,
    state_callback: Arc<RwLock<Option<Arc<dyn KeepStateCallback>>>>,
    state_rev: Arc<std::sync::atomic::AtomicU64>,
    pre_approved_hashes: PreApprovedHashes,
    session_store_path: Arc<std::sync::Mutex<Option<String>>>,
    descriptor_write_lock: Arc<std::sync::Mutex<()>>,
    pub(crate) bunker_config_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes load-modify-store of the relay config (relays + bunker
    /// permission grants) so a relay edit and an engine grant/revoke write do
    /// not clobber each other's section.
    pub(crate) relay_config_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes load-modify-persist of the certificate-pin store so concurrent
    /// stage/remove/clear FFI calls and `do_initialize`'s trust-on-first-use
    /// auto-pin cannot lose each other's update (last-writer-wins).
    cert_pin_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes the live-node lifecycle so the `(node, node_tasks)` pair is
    /// always swapped atomically. `do_initialize` (install) and
    /// `invalidate_live_node` (teardown) each hold this for their whole run, so
    /// a concurrent FFI init racing a delete/rotate cannot interleave into a
    /// node whose tasks were just aborted, or tasks pointing at a nulled node.
    node_lifecycle_lock: Arc<std::sync::Mutex<()>>,
    /// Whether an `ApproverHandler` holds this instance's approver state:
    /// two would overwrite each other's counters, request gate and anchors.
    pub(crate) approver_live: Arc<std::sync::atomic::AtomicBool>,
    /// Serializes active-share selection against deletion so the check-then-set
    /// in `set_active_share` (load a share, then mark it active) cannot
    /// interleave with a concurrent `delete_share_by_key`, which would leave the
    /// active pointer aimed at a just-deleted share. Always the outermost lock
    /// (the teardown it calls takes `node_lifecycle_lock`), so it cannot
    /// self-deadlock.
    active_share_lock: Arc<std::sync::Mutex<()>>,
}

struct PendingRequest {
    info: SignRequest,
    response_tx: mpsc::Sender<bool>,
}

#[derive(Clone)]
struct PendingContribution {
    network: String,
    initiator_pubkey: nostr_sdk::PublicKey,
    created_at: std::time::Instant,
}

/// Store the verifying-share set a node learned from its members' announces
/// with the share it was learned for, after checking it against the share
/// (`complete_verifying_shares`), so later starts bind every member at once.
/// The running node keeps going; only the stored public-key package changes.
fn store_learned_verifying_shares(
    storage: &dyn SecureStorage,
    group_pubkey: &[u8; 32],
    share_index: u16,
    verifying_shares: &std::collections::BTreeMap<u16, [u8; 33]>,
) -> Result<(), KeepMobileError> {
    let invalid = |msg: String| KeepMobileError::InvalidShare { msg };
    let key = hex::encode(group_pubkey);
    let data = storage.load_share_by_key(key.clone())?;
    let mut stored: StoredShareData =
        serde_json::from_slice(&data).map_err(|e| invalid(e.to_string()))?;
    let metadata: ShareMetadata =
        serde_json::from_str(&stored.metadata_json).map_err(|e| invalid(e.to_string()))?;
    if metadata.identifier != share_index || metadata.group_pubkey != *group_pubkey {
        return Err(invalid(
            "learned verifying shares are for another share".into(),
        ));
    }
    let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(&stored.key_package_bytes)
        .map_err(|e| invalid(format!("Invalid key package: {e}")))?;
    let pubkey_package =
        frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&stored.pubkey_package_bytes)
            .map_err(|e| invalid(format!("Invalid pubkey package: {e}")))?;
    let share = SharePackage::new(metadata.clone(), &key_package, &pubkey_package)
        .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
    let Some(complete) = keep_core::frost::completed_pubkey_package(&share, verifying_shares)
        .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
    else {
        return Ok(());
    };
    stored.pubkey_package_bytes = complete
        .serialize()
        .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
    let info = storage
        .list_all_shares()
        .into_iter()
        .find(|m| m.group_pubkey == group_pubkey.to_vec() && m.identifier == share_index)
        .unwrap_or_else(|| (&metadata).into());
    let serialized = serde_json::to_vec(&stored)
        .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;
    storage.store_share_by_key(key, serialized, info)
}

struct DescriptorContext {
    callbacks: Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
    storage: Arc<dyn SecureStorage>,
    node: Arc<KfpNode>,
    networks: Arc<std::sync::Mutex<HashMap<[u8; 32], String>>>,
    pending: Arc<std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>>,
}

struct StateContext {
    node: Arc<KfpNode>,
    pending: Arc<Mutex<Vec<PendingRequest>>>,
    callback: Arc<RwLock<Option<Arc<dyn KeepStateCallback>>>>,
    rev: Arc<std::sync::atomic::AtomicU64>,
}

impl StateContext {
    async fn push(&self, connection_status: &ConnectionStatus) {
        let Some(cb) = self.callback.read().await.clone() else {
            return;
        };

        let peers: Vec<PeerInfo> = self
            .node
            .peer_status()
            .into_iter()
            .map(|(share_index, status, name, _pubkey)| PeerInfo {
                share_index,
                name,
                status: convert_peer_status(status),
            })
            .collect();

        let pending_requests: Vec<SignRequest> = {
            let guard = self.pending.lock().await;
            guard.iter().map(|r| r.info.clone()).collect()
        };

        let rev = self.rev.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

        let state = KeepLiveState {
            rev,
            connection_status: connection_status.clone(),
            peers,
            pending_requests,
        };

        if let Err(e) = tokio::task::spawn_blocking(move || cb.on_state_changed(state))
            .await
            .unwrap_or_else(|e| {
                Err(KeepMobileError::FrostError {
                    msg: format!("State callback task panicked: {e}"),
                })
            })
        {
            tracing::error!("State callback error: {e}");
        }
    }
}

impl From<&ShareMetadata> for ShareMetadataInfo {
    fn from(metadata: &ShareMetadata) -> Self {
        ShareMetadataInfo {
            name: metadata.name.clone(),
            identifier: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            group_pubkey: metadata.group_pubkey.to_vec(),
            did_backup: metadata.did_backup,
        }
    }
}

#[uniffi::export]
impl KeepMobile {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, KeepMobileError> {
        init_logging();
        keep_frost_net::install_default_crypto_provider();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeepMobileError::InitializationFailed {
                msg: format!("Runtime: {e}"),
            })?;

        // A read fault here must not stop the app opening: without a KeepMobile
        // there is no account switcher, no export and no kill switch, and the
        // same read faults on every launch. The counters are left unknown, which
        // refuses the rules that consult them, rather than read as empty.
        let velocity = match persistence::load_velocity(&storage) {
            Ok(velocity) => Some(velocity),
            Err(e) => {
                tracing::error!("Velocity counters unreadable, spending limits will refuse: {e}");
                None
            }
        };
        let velocity = Arc::new(std::sync::Mutex::new(velocity));

        let mut evaluator = PolicyEvaluator::new(velocity.clone());
        Self::load_policy_into(&storage, &mut evaluator);

        let policy = Arc::new(std::sync::RwLock::new(evaluator));

        Ok(Self {
            node: Arc::new(RwLock::new(None)),
            node_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
            storage,
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            dkg_subkeys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            dkg_active: Arc::new(std::sync::Mutex::new(None)),
            dkg_run_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dkg_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            runtime,
            policy,
            velocity,
            descriptor_callbacks: Arc::new(RwLock::new(None)),
            health_callbacks: Arc::new(RwLock::new(None)),
            descriptor_networks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_contributions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            state_callback: Arc::new(RwLock::new(None)),
            state_rev: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pre_approved_hashes: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            session_store_path: Arc::new(std::sync::Mutex::new(None)),
            descriptor_write_lock: Arc::new(std::sync::Mutex::new(())),
            bunker_config_lock: Arc::new(std::sync::Mutex::new(())),
            relay_config_lock: Arc::new(std::sync::Mutex::new(())),
            cert_pin_lock: Arc::new(std::sync::Mutex::new(())),
            node_lifecycle_lock: Arc::new(std::sync::Mutex::new(())),
            approver_live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            active_share_lock: Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub fn set_session_store_path(&self, path: String) -> Result<(), KeepMobileError> {
        if std::path::Path::new(&path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(KeepMobileError::InvalidInput {
                msg: format!("Session store path contains parent traversal: {path}"),
            });
        }
        let mut guard = self.session_store_path.lock().unwrap_or_else(|poisoned| {
            tracing::error!("session_store_path lock poisoned: {poisoned:?}");
            poisoned.into_inner()
        });
        *guard = Some(path);
        Ok(())
    }

    pub fn initialize(&self, relays: Vec<String>) -> Result<(), KeepMobileError> {
        self.do_initialize(relays, None)
    }

    pub fn initialize_with_proxy(
        &self,
        relays: Vec<String>,
        proxy_host: String,
        proxy_port: u16,
    ) -> Result<(), KeepMobileError> {
        let proxy = parse_loopback_proxy(&proxy_host, proxy_port)?;
        self.do_initialize(relays, Some(proxy))
    }

    pub fn import_share(
        &self,
        data: String,
        passphrase: String,
        name: String,
    ) -> Result<ShareInfo, KeepMobileError> {
        if data.len() > MAX_IMPORT_DATA_SIZE {
            return Err(KeepMobileError::InvalidShare {
                msg: "Import data exceeds maximum size".into(),
            });
        }

        Self::validate_share_name(&name)?;

        let share_count = self.storage.list_all_shares().len();
        if share_count >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        let passphrase = Zeroizing::new(passphrase);
        let export = ShareExport::parse(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        if export.ciphersuite != keep_core::frost::Ciphersuite::Secp256k1Tr {
            return Err(KeepMobileError::InvalidShare {
                msg: "Only secp256k1 (Bitcoin/Nostr) shares are supported on mobile".into(),
            });
        }

        let share = export
            .to_share(&passphrase, &name)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        self.store_share_package(&share)
    }

    pub fn import_nsec(&self, nsec: Vec<u8>, name: String) -> Result<ShareInfo, KeepMobileError> {
        use nostr_sdk::prelude::{FromBech32, SecretKey};
        // Accept the nsec as wipeable bytes (a Kotlin ByteArray) rather than an
        // immutable String, and decode it to the secret key here so the raw hex
        // form is never handed back across the FFI to the caller.
        let nsec = Zeroizing::new(nsec);
        let nsec = std::str::from_utf8(&nsec).map_err(|_| KeepMobileError::InvalidShare {
            msg: "nsec must be valid UTF-8".into(),
        })?;
        let secret = SecretKey::from_bech32(nsec).map_err(|_| KeepMobileError::InvalidShare {
            msg: "invalid nsec".into(),
        })?;
        let hex_key = Zeroizing::new(secret.to_secret_hex());
        self.do_import_nsec(&hex_key, name, None)
    }

    pub fn generate_mnemonic(&self, word_count: u32) -> Result<Vec<u8>, KeepMobileError> {
        // Return the generated phrase as bytes so the caller (Kotlin) can hold it in a
        // wipeable ByteArray instead of an immutable String. The internal phrase is
        // zeroized on drop; only the returned bytes leave the crate.
        let mnemonic = keep_core::mnemonic::generate_mnemonic(word_count)
            .map_err(|e| KeepMobileError::InvalidInput { msg: e.to_string() })?;
        Ok(mnemonic.as_bytes().to_vec())
    }

    pub fn validate_mnemonic(&self, mnemonic: Vec<u8>) -> Result<(), KeepMobileError> {
        // Accept the mnemonic as wipeable bytes (a Kotlin ByteArray) rather than an
        // immutable String that lingers on the JVM heap.
        let mnemonic = Zeroizing::new(mnemonic);
        let mnemonic =
            std::str::from_utf8(&mnemonic).map_err(|_| KeepMobileError::InvalidInput {
                msg: "mnemonic must be valid UTF-8".into(),
            })?;
        keep_core::mnemonic::validate_mnemonic(mnemonic)
            .map_err(|e| KeepMobileError::InvalidInput { msg: e.to_string() })
    }

    pub fn create_account_from_mnemonic(
        &self,
        mnemonic: Vec<u8>,
        passphrase: String,
        name: String,
    ) -> Result<ShareInfo, KeepMobileError> {
        self.create_account_from_mnemonic_with_index(mnemonic, passphrase, name, 0)
    }

    pub fn create_account_from_mnemonic_with_index(
        &self,
        mnemonic: Vec<u8>,
        mut passphrase: String,
        name: String,
        account_index: u32,
    ) -> Result<ShareInfo, KeepMobileError> {
        Self::validate_share_name(&name)?;
        if self.storage.list_all_shares().len() >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        // The mnemonic arrives as wipeable bytes; borrow it as UTF-8 to derive the key
        // and keep a zeroizing copy for storage. No plaintext mnemonic String is created.
        let mnemonic = Zeroizing::new(mnemonic);
        let mnemonic_str =
            std::str::from_utf8(&mnemonic).map_err(|_| KeepMobileError::InvalidInput {
                msg: "mnemonic must be valid UTF-8".into(),
            })?;
        let mnemonic_bytes = Zeroizing::new(mnemonic.to_vec());
        let key = keep_core::nip06::derive_nostr_key(mnemonic_str, &passphrase, account_index)
            .map_err(|e| KeepMobileError::InvalidInput { msg: e.to_string() });
        passphrase.zeroize();
        let key = key?;
        let hex_key = Zeroizing::new(hex::encode(*key));
        self.do_import_nsec(&hex_key, name, Some(mnemonic_bytes))
    }

    pub fn set_signing_pre_approved(&self, message: Vec<u8>) {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(&message).into();
        let now = std::time::Instant::now();
        let mut guard = lock_pre_approved(&self.pre_approved_hashes);
        if guard.len() >= MAX_PRE_APPROVED_HASHES {
            if let Some(&oldest) = guard.iter().min_by_key(|(_, &t)| t).map(|(k, _)| k) {
                guard.remove(&oldest);
            }
        }
        guard.insert(hash, now);
    }

    /// Pre-approve a specific Nostr event (by its computed event id) so the next
    /// matching sign request auto-approves without prompting. Convenience wrapper
    /// over [`set_signing_pre_approved`] for NIP-55 callers holding event JSON.
    pub fn pre_approve_nostr_event(&self, event_json: String) -> Result<(), KeepMobileError> {
        let event: serde_json::Value =
            serde_json::from_str(&event_json).map_err(|_| KeepMobileError::InvalidSession)?;
        crate::nip55::validate_nostr_event(&event)?;
        let event_hash = crate::nip55::compute_nostr_event_id(&event)?;
        self.set_signing_pre_approved(event_hash.to_vec());
        Ok(())
    }

    pub fn clear_signing_pre_approval(&self) {
        self.pre_approved_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn get_pending_requests(&self) -> Vec<SignRequest> {
        self.runtime.block_on(async {
            self.pending_requests
                .lock()
                .await
                .iter()
                .map(|r| r.info.clone())
                .collect()
        })
    }

    pub fn approve_request(&self, request_id: String) -> Result<(), KeepMobileError> {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            let idx = pending
                .iter()
                .position(|r| r.info.id == request_id)
                .ok_or(KeepMobileError::RequestNotFound)?;

            let request = pending.remove(idx);
            let _ = request.response_tx.send(true).await;
            Ok(())
        })
    }

    pub fn reject_request(&self, request_id: String) {
        self.runtime.block_on(async {
            let mut pending = self.pending_requests.lock().await;
            if let Some(idx) = pending.iter().position(|r| r.info.id == request_id) {
                let request = pending.remove(idx);
                let _ = request.response_tx.send(false).await;
            }
        });
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let Some(node) = node_guard.as_ref() else {
                return Vec::new();
            };

            node.peer_status()
                .into_iter()
                .map(|(share_index, status, name, _pubkey)| PeerInfo {
                    share_index,
                    name,
                    status: convert_peer_status(status),
                })
                .collect()
        })
    }

    pub fn has_share(&self) -> bool {
        self.storage.has_share()
    }

    pub fn get_share_info(&self) -> Option<ShareInfo> {
        self.storage.get_share_metadata().map(|m| ShareInfo {
            name: m.name,
            share_index: m.identifier,
            threshold: m.threshold,
            total_shares: m.total_shares,
            group_pubkey: hex::encode(&m.group_pubkey),
        })
    }

    pub fn delete_share(&self) -> Result<(), KeepMobileError> {
        self.storage.delete_share()
    }

    pub fn export_share(&self, passphrase: String) -> Result<String, KeepMobileError> {
        let passphrase = Zeroizing::new(passphrase);
        let share = self.load_share_package()?;
        let export = ShareExport::from_share(&share, &passphrase)
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;
        export
            .to_text()
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })
    }

    pub fn export_ncryptsec(&self, password: Vec<u8>) -> Result<String, KeepMobileError> {
        // Accept the password as raw bytes so the caller (Kotlin) can pass a wipeable
        // ByteArray instead of an immutable String that lingers on the JVM heap. The
        // bytes are borrowed as UTF-8 in place; no owned String copy is made here.
        let password = Zeroizing::new(password);
        let password =
            std::str::from_utf8(&password).map_err(|_| KeepMobileError::InvalidInput {
                msg: "password must be valid UTF-8".into(),
            })?;
        let share = self.load_share_package()?;

        if share.metadata.threshold != 1 || share.metadata.total_shares != 1 {
            return Err(KeepMobileError::InvalidInput {
                msg: "NIP-49 export is only supported for single-key (nsec) shares".into(),
            });
        }

        let key_package = share
            .key_package()
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

        let share_bytes = Zeroizing::new(key_package.signing_share().serialize());
        let secret: Zeroizing<[u8; 32]> =
            Zeroizing::new(share_bytes.as_slice().try_into().map_err(|_| {
                KeepMobileError::EncryptionError {
                    msg: "unexpected signing share length".into(),
                }
            })?);

        keep_core::keys::nip49::encrypt(&secret, password, Some(14))
            .map_err(|e| KeepMobileError::EncryptionError { msg: e.to_string() })
    }

    pub fn list_shares(&self) -> Vec<StoredShareInfo> {
        self.storage
            .list_all_shares()
            .into_iter()
            .filter_map(|m| self.load_stored_share_info(hex::encode(&m.group_pubkey)))
            .collect()
    }

    pub fn get_active_share(&self) -> Option<StoredShareInfo> {
        let key = self.storage.get_active_share_key()?;
        self.load_stored_share_info(key)
    }

    pub fn get_active_share_metadata(&self) -> Option<ShareMetadataInfo> {
        let key = self.resolve_active_share().ok()?;
        // As in `load_stored_share_info`: an active-share pointer that resolves
        // but whose record is unreadable or malformed is corruption, not absence,
        // so log it rather than returning a bare `None` (#792).
        let data = match self.storage.load_share_by_key(key.clone()) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("failed to load active share for key {key}: {e}");
                return None;
            }
        };
        let stored: StoredShareData = match serde_json::from_slice(&data) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::warn!("corrupt active share data for key {key}: {e}");
                return None;
            }
        };
        let metadata: ShareMetadata = match serde_json::from_str(&stored.metadata_json) {
            Ok(metadata) => metadata,
            Err(e) => {
                tracing::warn!("corrupt active share metadata for key {key}: {e}");
                return None;
            }
        };
        Some((&metadata).into())
    }

    /// Abort the running node's tasks, drop pending sign requests, and null the
    /// live node so the next active share re-initializes a fresh node instead of
    /// leaving the stale one signing on the relays. Aborting the tasks lets them
    /// release their Arc clones, so the node drops and its share material
    /// zeroizes once the runtime finishes cancelling them.
    fn invalidate_live_node(&self) {
        // Serialize teardown against a concurrent `do_initialize` so the
        // (node, node_tasks) pair is swapped atomically. Held for the whole fn.
        let _lifecycle = self
            .node_lifecycle_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for handle in self
            .node_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            handle.abort();
        }
        self.runtime.block_on(async {
            self.pending_requests.lock().await.clear();
            *self.node.write().await = None;
        });
    }

    pub fn set_active_share(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        // Serialize the load-then-set against a concurrent delete so the active
        // pointer cannot be aimed at a share deleted in between.
        let _active = self
            .active_share_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.storage.load_share_by_key(group_pubkey.clone())?;
        self.storage.set_active_share_key(Some(group_pubkey))?;

        self.invalidate_live_node();

        Ok(())
    }

    pub fn delete_share_by_key(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        // Held for the whole delete so it cannot interleave with the
        // load-then-set in `set_active_share`.
        let _active = self
            .active_share_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let is_active = self
            .storage
            .get_active_share_key()
            .is_some_and(|k| constant_time_eq(k.as_bytes(), group_pubkey.as_bytes()));

        if is_active {
            self.storage.set_active_share_key(None)?;
        }

        // Attempt the removal first, then tear down whatever the outcome.
        //
        // Unconditional over the pointer, because the pointer does not say
        // which share the live node was built from: `load_share_package`
        // resolves the share when no pointer is set, so a node can be running
        // on a share the pointer never named, and gating teardown on the
        // pointer left that node holding the deleted share's key material,
        // still subscribed to the relays and still able to contribute signature
        // shares, with any already-queued request still approvable.
        //
        // After the removal, because `do_initialize` holds
        // `node_lifecycle_lock` across both the share load and the node install
        // while taking no `active_share_lock`. Tearing down before the record is
        // gone leaves a window where a concurrent initialize resolves the
        // still-present share and installs a node on it; doing it after means
        // such an initialize either no longer finds the record or is serialized
        // behind this teardown by that lock.
        //
        // Unconditional over the result too, because `delete_share_by_key` is
        // not atomic. The Android implementation clears the share data, then
        // deletes the keystore aliases, then rewrites the registry, and either
        // of the last two can fail after the data is already gone. So an `Err`
        // does not mean the share survived, and skipping the teardown on it
        // would leave the live node holding the only remaining copy of a share
        // the platform has already destroyed, while the caller is told the
        // delete failed. Tearing down costs a reconnect either way.
        let deleted = self.storage.delete_share_by_key(group_pubkey);
        self.invalidate_live_node();
        deleted
    }

    // Load-modify-store without locking; acceptable in single-user mobile context
    pub fn mark_share_backed_up(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let data = self.storage.load_share_by_key(group_pubkey.clone())?;
        let mut stored: StoredShareData = serde_json::from_slice(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let mut metadata: keep_core::frost::ShareMetadata =
            serde_json::from_str(&stored.metadata_json)
                .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        metadata.mark_backed_up();

        stored.metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        self.storage
            .store_share_by_key(group_pubkey, serialized, (&metadata).into())?;
        Ok(())
    }

    // Load-modify-store without locking; acceptable in single-user mobile context
    pub fn rename_share(&self, group_pubkey: String, name: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(KeepMobileError::InvalidShare {
                msg: "Share name must not be empty".into(),
            });
        }
        Self::validate_share_name(name)?;

        let data = self.storage.load_share_by_key(group_pubkey.clone())?;
        let mut stored: StoredShareData = serde_json::from_slice(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let mut metadata: keep_core::frost::ShareMetadata =
            serde_json::from_str(&stored.metadata_json)
                .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        metadata.name = name.to_string();

        stored.metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        self.storage
            .store_share_by_key(group_pubkey, serialized, (&metadata).into())?;
        Ok(())
    }

    // Caller is responsible for re-authentication before calling this method
    pub fn get_seed_words(&self, group_pubkey: String) -> Result<Option<Vec<u8>>, KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let data = self.storage.load_share_by_key(group_pubkey)?;
        let stored: StoredShareData = serde_json::from_slice(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        stored
            .plaintext_mnemonic
            .map(|bytes| {
                // Validate UTF-8 (as before) but return the raw bytes so the caller holds a
                // wipeable ByteArray instead of an immutable String on the JVM heap.
                std::str::from_utf8(&bytes).map_err(|_| KeepMobileError::StorageError {
                    msg: "mnemonic contains invalid UTF-8".to_string(),
                })?;
                Ok(bytes.to_vec())
            })
            .transpose()
    }

    /// Generates a threshold key set using a trusted dealer.
    ///
    /// **The full private key exists on this device during generation.** Every
    /// share is derived here before being distributed, so a device compromised
    /// at this moment exposes the key regardless of the threshold chosen. The
    /// threshold protects signing afterwards; it does not protect generation.
    ///
    /// Prefer distributed key generation where each participant contributes
    /// entropy and the whole key is never assembled anywhere. Use this only when
    /// that is not available, and treat the generating device accordingly.
    pub fn frost_generate(
        &self,
        threshold: u16,
        total_shares: u16,
        name: String,
        passphrase: String,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let config = CoreThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate(&name)?;

        let passphrase = Zeroizing::new(passphrase);
        Self::build_generation_result(&shares, &passphrase)
    }

    /// Splits an existing private key into threshold shares using a trusted
    /// dealer.
    ///
    /// **The key is present in full on this device**, both as the input being
    /// split and while the shares are derived. The same caveat as
    /// [`Self::frost_generate`] applies, and additionally the key existed before
    /// this call, so it may already be recorded elsewhere: splitting it does not
    /// retract earlier copies.
    pub fn frost_split(
        &self,
        mut existing_key: String,
        threshold: u16,
        total_shares: u16,
        name: String,
        passphrase: String,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        let passphrase = Zeroizing::new(passphrase);
        let name_result = Self::validate_share_name(&name);
        let key_result = hex::decode(&existing_key).map_err(|_| KeepMobileError::InvalidShare {
            msg: "Invalid hex encoding for existing key".into(),
        });
        existing_key.zeroize();
        name_result?;
        let mut key_bytes = key_result?;

        if key_bytes.len() != 32 {
            key_bytes.zeroize();
            return Err(KeepMobileError::InvalidShare {
                msg: "Existing key must be exactly 32 bytes".into(),
            });
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&key_bytes);
        key_bytes.zeroize();

        let config = CoreThresholdConfig::new(threshold, total_shares)?;
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.split_existing(&secret, &name)?;

        Self::build_generation_result(&shares, &passphrase)
    }

    /// FFI split, option B (§8): mint (or re-mint) this device's per-group DKG
    /// signing subkey and return only its pubkey hex. The secret stays in Rust,
    /// held in memory keyed by `group_name`, and never crosses the Kotlin
    /// boundary. Each participant runs this, exchanges the printed pubkeys out of
    /// band, and the coordinator assembles them into the `DkgConfig` roster that
    /// `frost_run_dkg` consumes. Re-running before `frost_run_dkg` replaces the
    /// pending subkey for that group.
    pub fn frost_dkg_begin(&self, group_name: String) -> Result<String, KeepMobileError> {
        if group_name.is_empty() || group_name.chars().count() > MAX_SHARE_NAME_LENGTH {
            return Err(KeepMobileError::FrostError {
                msg: format!("group name must be 1..={MAX_SHARE_NAME_LENGTH} characters"),
            });
        }
        let keys = nostr_sdk::Keys::generate();
        let secret = Zeroizing::new(keys.secret_key().secret_bytes());
        self.dkg_subkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_name, secret);
        Ok(keys.public_key().to_hex())
    }

    /// Signal a cancel to the in-flight `frost_run_dkg` identified by `run_id`
    /// (the id delivered via `DkgProgressUpdate::Started`). The coordinator polls
    /// the run's flag between relay fetches (§8/§9) and aborts promptly with a
    /// cancelled error, tearing down the transport cleanly, instead of leaving a
    /// live session for a `reset` to corrupt. A cancel that arrives once this
    /// device holds every confirmation and a relay accepted its own is not
    /// honored, since peers can already finalize with it: the run completes and
    /// the share is kept. A `run_id` that does not match the
    /// active run is ignored, so a cancel issued for a run that has since finished
    /// cannot abort a later run (§8: no wiping a concurrent run).
    pub fn frost_cancel_dkg(&self, run_id: u64) {
        let active = self.dkg_active.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(run) = active.as_ref() {
            if run.id == run_id {
                run.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Discard the pending DKG subkey minted by `frost_dkg_begin` for
    /// `group_name` without running the ceremony. A begin that is never followed
    /// by `frost_run_dkg` (the user toggles Start/Join, or the ceremony is
    /// abandoned) would otherwise leave its minted subkey secret stashed for the
    /// process lifetime; the client calls this on abandonment to zeroize and drop
    /// it. Idempotent: a group with no pending subkey is a no-op.
    pub fn frost_dkg_discard(&self, group_name: String) {
        self.dkg_subkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&group_name);
    }

    /// Run a full relay-driven DKG to create a new group on this device, then
    /// persist the resulting share. Every participant calls this concurrently
    /// with the same invite roster (`config.roster`) and relays but its own
    /// `config.our_index`; the crypto rounds and roster-authenticated coordination
    /// run in the shared `keep_frost_net::run_software_dkg` (see [`dkg`]) so no
    /// device ever holds the whole key and mobile/CLI cannot drift. `progress`
    /// receives live state; a run that fails reports [`DkgProgressUpdate::Failed`]
    /// before returning the error, and `Complete` fires only after the share is
    /// persisted (§6).
    ///
    /// Returns the stored share on success. `timeout_secs` bounds each round
    /// (floored to 30s to tolerate slow peers and biometric prompts).
    pub fn frost_run_dkg(
        &self,
        config: DkgConfig,
        name: String,
        passphrase: String,
        timeout_secs: u64,
        progress: Arc<dyn dkg::DkgProgressCallback>,
    ) -> Result<ShareInfo, KeepMobileError> {
        // Single-flight: `frost_run_dkg` shares `dkg_active`/`dkg_subkeys`, so a
        // second concurrent call would clobber the active run's identity. Reject
        // it, and on every exit path deregister the active run before releasing
        // the flag so a next run cannot observe a stale identity.
        struct DkgInFlightGuard {
            in_flight: Arc<std::sync::atomic::AtomicBool>,
            active: Arc<std::sync::Mutex<Option<DkgActiveRun>>>,
        }
        impl Drop for DkgInFlightGuard {
            fn drop(&mut self) {
                *self.active.lock().unwrap_or_else(|p| p.into_inner()) = None;
                self.in_flight
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
        if self
            .dkg_in_flight
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(KeepMobileError::FrostError {
                msg: "a DKG run is already in progress".into(),
            });
        }
        let _in_flight = DkgInFlightGuard {
            in_flight: self.dkg_in_flight.clone(),
            active: self.dkg_active.clone(),
        };

        // Pre-flight the persistence constraints before the multi-round network
        // run so an invalid name or a full store fails fast, rather than after
        // peers have already completed a group this device would discard.
        Self::validate_share_name(&name)?;
        if self.storage.list_all_shares().len() >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        // The pending stash is a single global slot, so a run that completed
        // here would overwrite an earlier unrecovered stash and lose that share
        // for good. Refuse to start until the prior share is recovered; fail
        // closed on a load error so a corrupt stash is never silently clobbered.
        if persistence::load_pending_dkg_marker(&self.storage, DKG_PENDING_MARKER_KEY)?.is_some() {
            return Err(KeepMobileError::StorageError {
                msg: "a completed DKG share is pending recovery; recover it before starting a new run"
                    .into(),
            });
        }

        // Load this device's pending subkey (from `frost_dkg_begin`) and rebuild
        // its keypair. Clone (don't consume) here so a preflight failure below
        // — relay TLS pinning or proxy setup — leaves the subkey stashed for a
        // cheap retry rather than forcing a re-mint (and a fresh roster across
        // every participant). Fail before any network I/O if the two-call
        // sequence was skipped.
        let subkey = {
            let map = self.dkg_subkeys.lock().unwrap_or_else(|p| p.into_inner());
            let secret = map.get(&config.group_name).cloned().ok_or_else(|| {
                KeepMobileError::FrostError {
                    msg: "call frost_dkg_begin for this group before frost_run_dkg".into(),
                }
            })?;
            let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&*secret).map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("stored DKG subkey is invalid: {e}"),
                }
            })?;
            nostr_sdk::Keys::new(sk.into())
        };

        // Route through the configured loopback SOCKS proxy when enabled (§7),
        // mirroring the signing path's proxy. Resolved before the probe below,
        // which dials through the same proxy.
        let stored_proxy = persistence::load_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();
        let proxy = if stored_proxy.enabled {
            Some(parse_loopback_proxy("127.0.0.1", stored_proxy.port)?)
        } else {
            None
        };

        // Verify + pin each relay's TLS cert before connecting (§7), holding the
        // cert-pin lock only for that brief read-modify-write, not the whole run.
        // The probe and the live transport's pin set are read under one lock
        // acquisition, and both before the single-use subkey below is consumed:
        // a storage fault while reading pins must not strand a half-started
        // ceremony, and a concurrent FFI pin edit must not land between the two
        // reads.
        let (relays, pinning) = {
            let _cert = self.cert_pin_lock.lock().unwrap_or_else(|p| p.into_inner());
            let relays = self
                .runtime
                .block_on(self.verify_and_pin_relays(&config.relays, proxy))?;
            (relays, self.live_pinning()?)
        };

        // Preflight has passed and the ceremony is about to start, so consume the
        // subkey now: it is single-use for this run — a completed or failed
        // *ceremony* must not leave it stashed for the process lifetime (a retry
        // re-mints via `frost_dkg_begin`). A concurrent `frost_dkg_discard` that
        // raced the preflight above simply makes this a no-op; we proceed with the
        // keypair already cloned.
        self.dkg_subkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&config.group_name);

        // Mint this run's identity and a fresh cancel flag, then register it so
        // `frost_cancel_dkg(run_id)` targets only this run. The id reaches the UI
        // via `Started` so it can issue a matching cancel.
        let run_id = self
            .dkg_run_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *self.dkg_active.lock().unwrap_or_else(|p| p.into_inner()) = Some(DkgActiveRun {
            id: run_id,
            cancel: cancel.clone(),
        });
        progress.on_progress(DkgProgressUpdate::Started { run_id });

        let passphrase = Zeroizing::new(passphrase);
        let timeout = Duration::from_secs(timeout_secs.max(30));
        let outcome = self.runtime.block_on(dkg::run_dkg(
            &subkey,
            &config,
            &relays,
            proxy,
            &name,
            &passphrase,
            timeout,
            &cancel,
            progress.clone(),
            Some(pinning),
        ));

        match outcome {
            // §6: persist first, and surface `Complete` only once the share is
            // stored. A storage failure here still emits `Failed` and never
            // `Complete`, so the group never looks ready without a stored share.
            Ok(result) => {
                // Stash the finalized share durably before import so a storage
                // failure here doesn't silently drop a share the peers already
                // treat as live, AND make it recoverable (§8): the ceremony
                // passphrase is ephemeral, so it is stashed inside the auth-gated
                // secret and the blob's at-rest protection is bound to the device
                // vault, not the passphrase. `recover_dkg_share` then needs only a
                // vault unlock. Write the auth-gated secret first, then the
                // non-sensitive marker: the marker is what gates recovery, so a
                // half-write that leaves a secret without a marker is the safe
                // failure (invisible, overwritten by the next run) rather than a
                // marker pointing at a secret that never landed. Best-effort — if
                // the stash write fails the import below still gets its chance.
                let secret = persistence::PendingDkgSecret {
                    schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                    share_export: Zeroizing::new(result.share_export.clone()),
                    vault_passphrase: Some(passphrase.clone()),
                };
                let marker = persistence::PendingDkgMarker {
                    schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                    name: name.clone(),
                    group_pubkey_hex: result.group_pubkey.clone(),
                    vault_protected: true,
                };
                if let Err(e) = persistence::persist_pending_dkg_secret(
                    &self.storage,
                    DKG_PENDING_SECRET_KEY,
                    &secret,
                ) {
                    tracing::warn!("failed to stash pending DKG secret before import: {e}");
                } else if let Err(e) = persistence::persist_pending_dkg_marker(
                    &self.storage,
                    DKG_PENDING_MARKER_KEY,
                    &marker,
                ) {
                    tracing::warn!("failed to stash pending DKG marker before import: {e}");
                }

                match self.import_share(result.share_export, passphrase.to_string(), name) {
                    Ok(info) => {
                        // Import confirmed; clear the stash (best-effort — a stale
                        // stash is recovered idempotently, never lost).
                        if let Err(e) = persistence::delete_pending_dkg_stash(
                            &self.storage,
                            DKG_PENDING_MARKER_KEY,
                            DKG_PENDING_SECRET_KEY,
                        ) {
                            tracing::warn!("failed to clear pending DKG stash after import: {e}");
                        }
                        progress.on_progress(DkgProgressUpdate::Complete {
                            group_pubkey: result.group_pubkey,
                        });
                        Ok(info)
                    }
                    Err(e) => {
                        // Stash retained: `recover_dkg_share` can finish the
                        // import on next launch. Never emit `Complete`.
                        progress.on_progress(DkgProgressUpdate::Failed {
                            reason: e.to_string(),
                        });
                        Err(e)
                    }
                }
            }
            Err(e) => {
                progress.on_progress(DkgProgressUpdate::Failed {
                    reason: e.to_string(),
                });
                Err(e)
            }
        }
    }

    /// A DKG share whose ceremony completed but whose import into share storage
    /// was never confirmed. Present after a storage failure during
    /// `frost_run_dkg`. Recovering it via `recover_dkg_share` needs the ceremony
    /// passphrase, which the manual-import path has but the DKG path does not
    /// (it is ephemeral); when it is unavailable the app clears the stash with
    /// `discard_pending_dkg_share`. `Ok(None)` when nothing is pending; a load
    /// error is surfaced rather than masked as `None` so a corrupt or
    /// momentarily-unreadable stash can't make a live share look absent — the
    /// exact loss this feature exists to prevent — letting the app retry.
    pub fn pending_dkg_share(&self) -> Result<Option<PendingShareInfo>, KeepMobileError> {
        Ok(
            persistence::load_pending_dkg_marker(&self.storage, DKG_PENDING_MARKER_KEY)?.map(
                |marker| PendingShareInfo {
                    name: marker.name,
                    group_pubkey: marker.group_pubkey_hex,
                    vault_protected: marker.vault_protected,
                },
            ),
        )
    }

    /// Finish importing a share stashed by `frost_run_dkg` after its ceremony
    /// completed but its import failed. Loading the secret costs a vault unlock
    /// on the DKG path (its alias is auth-gated). For a vault-protected stash the
    /// ephemeral ceremony passphrase rides inside the secret, so `passphrase` is
    /// ignored and recovery needs only that unlock; for a passphrase-protected
    /// stash (manual QR import) the caller must supply the passphrase they know.
    /// Clears the stash on success. Errors if nothing is pending.
    pub fn recover_dkg_share(
        &self,
        passphrase: Option<String>,
    ) -> Result<ShareInfo, KeepMobileError> {
        let marker = persistence::load_pending_dkg_marker(&self.storage, DKG_PENDING_MARKER_KEY)?
            .ok_or_else(|| KeepMobileError::StorageError {
            msg: "no pending DKG share to recover".into(),
        })?;
        let secret = persistence::load_pending_dkg_secret(&self.storage, DKG_PENDING_SECRET_KEY)?
            .ok_or_else(|| KeepMobileError::StorageError {
            msg: "pending DKG marker has no matching secret to recover".into(),
        })?;

        let passphrase = if marker.vault_protected {
            secret
                .vault_passphrase
                .ok_or_else(|| KeepMobileError::StorageError {
                    msg: "vault-protected stash is missing its ceremony passphrase".into(),
                })?
        } else {
            Zeroizing::new(passphrase.ok_or_else(|| KeepMobileError::StorageError {
                msg: "a passphrase is required to recover this share".into(),
            })?)
        };

        let info = self.import_share(
            secret.share_export.to_string(),
            passphrase.to_string(),
            marker.name,
        )?;

        if let Err(e) = persistence::delete_pending_dkg_stash(
            &self.storage,
            DKG_PENDING_MARKER_KEY,
            DKG_PENDING_SECRET_KEY,
        ) {
            tracing::warn!("failed to clear pending DKG stash after recovery: {e}");
        }
        Ok(info)
    }

    /// Abandon a pending DKG share, re-enabling `frost_run_dkg`. The pending
    /// guard is fail-closed, so a stash that can't be recovered — its record is
    /// corrupt, or the vault can't be unlocked — would otherwise refuse every
    /// future run for good. This is the deliberate escape hatch: it discards the
    /// share permanently, so callers must gate it behind an explicit user
    /// confirmation. Idempotent; succeeds when nothing is pending.
    pub fn discard_pending_dkg_share(&self) -> Result<(), KeepMobileError> {
        persistence::delete_pending_dkg_stash(
            &self.storage,
            DKG_PENDING_MARKER_KEY,
            DKG_PENDING_SECRET_KEY,
        )
    }

    pub fn import_policy(&self, bundle_hex: String) -> Result<PolicyInfo, KeepMobileError> {
        const MAX_BUNDLE_HEX_LEN: usize = 8192;
        if bundle_hex.len() > MAX_BUNDLE_HEX_LEN {
            return Err(KeepMobileError::InvalidPolicy {
                msg: format!(
                    "Bundle hex too large: {} bytes (max {})",
                    bundle_hex.len(),
                    MAX_BUNDLE_HEX_LEN
                ),
            });
        }

        let bundle_bytes =
            hex::decode(&bundle_hex).map_err(|e| KeepMobileError::InvalidPolicy {
                msg: format!("Invalid hex: {e}"),
            })?;

        let bundle = PolicyBundle::from_bytes(&bundle_bytes)?;
        bundle.verify_signature()?;
        bundle.verify_hash()?;
        bundle.verify_timestamp()?;

        // A transient fault must not push the caller into discarding a
        // warden-signed policy, so the record gets another read first.
        self.reload_policy_if_transient()?;

        let mut policy = self.policy_write_lock()?;
        // Refused when the stored record cannot say how old it is, rather than
        // installed over it. The rollback check below needs a baseline, and a
        // record that failed verification is not one: accepting the install
        // would let anyone who can corrupt the record roll the policy back to
        // an older bundle that still carries a real warden signature. An
        // expired bundle is attributed, so it is still a baseline and a
        // replacement installs over it normally.
        //
        // Worth being exact about what this buys: `delete_policy` needs no
        // authorization, so this raises the cost of that rollback from nothing
        // to one more call rather than closing it. Closing it needs an epoch
        // that outlives deletion, which is follow-up work.
        if policy.fault().is_some() && policy.rollback_baseline().is_none() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Refusing to replace a policy that cannot be checked against. \
                      Delete the stored policy first."
                    .into(),
            });
        }
        bundle.verify_trusted_warden(policy.trusted_wardens())?;
        bundle.verify_version_upgrade(policy.rollback_baseline())?;

        let info = bundle.to_policy_info();
        policy.set_policy(bundle.clone());
        persistence::persist_policy(&self.storage, &bundle)?;

        Ok(info)
    }

    /// The policy in force, which is `None` both when none is configured and
    /// when the stored one cannot be trusted. Use [`Self::policy_status`] to
    /// tell those apart; they behave as opposites.
    pub fn get_policy_info(&self) -> Option<PolicyInfo> {
        self.policy
            .read()
            .ok()?
            .policy()
            .map(|b| b.to_policy_info())
    }

    /// Whether a policy is configured, in force, or stored and untrustworthy.
    ///
    /// A faulted record refuses every spend, so reporting it as no policy would
    /// leave a caller unable to explain the refusals. Retries an unreadable
    /// record first, so a transient read fault is not reported as a fault.
    pub fn policy_status(&self) -> Result<PolicyStatus, KeepMobileError> {
        self.reload_policy_if_transient()?;
        Ok(self.policy_read_lock()?.status())
    }

    /// Removes the stored policy, and is the only way out of a record that will
    /// not verify. Deliberately an explicit act: it discards a policy a warden
    /// signed, so it should not happen as a side effect of a corrupt record.
    pub fn delete_policy(&self) -> Result<(), KeepMobileError> {
        // The record goes first and the error is surfaced. Clearing memory on a
        // delete that did not happen reports success, opens the gate for this
        // process, and faults again at the next launch. One guard spans both,
        // so a reload cannot land between them and re-arm the fault after this
        // has already returned.
        let mut policy = self.policy_write_lock()?;
        match self.storage.delete_share_by_key(POLICY_STORAGE_KEY.into()) {
            Ok(()) | Err(KeepMobileError::StorageNotFound) => {}
            Err(e) => return Err(e),
        }
        policy.clear_policy();
        Ok(())
    }

    pub fn evaluate_policy(
        &self,
        ctx: TransactionContext,
    ) -> Result<PolicyDecision, KeepMobileError> {
        self.reload_velocity_if_unknown()?;
        self.reload_policy_if_transient()?;
        self.policy_read_lock()?.evaluate(&ctx)
    }

    pub fn record_policy_transaction(&self, amount_sats: u64) -> Result<(), KeepMobileError> {
        self.reload_velocity_if_unknown()?;
        self.policy_read_lock()?.record_transaction(amount_sats)?;
        let velocity = self.velocity_lock()?;
        let tracker = velocity
            .as_ref()
            .ok_or_else(|| KeepMobileError::StorageError {
                msg: "Velocity counters went unknown between recording and persisting".into(),
            })?;
        persistence::persist_velocity(&self.storage, tracker)
    }

    /// Resets the spending counters, and is one of the two ways back from
    /// counters that could not be read: it overwrites the unreadable record, so
    /// the limits go from refusing to enforcing a known-empty history. The other
    /// is [`Self::reload_velocity_if_unknown`], which keeps the real history and
    /// so is tried first on every decision.
    ///
    /// The write lands before the counters change. Nothing here may leave them
    /// reading as empty on a path that returns an error, because that is the
    /// refusal lifted against a history still unknown.
    pub fn clear_velocity_tracker(&self) -> Result<(), KeepMobileError> {
        let mut velocity = self.velocity_lock()?;
        let fresh = VelocityTracker::new();
        persistence::persist_velocity(&self.storage, &fresh)?;
        *velocity = Some(fresh);
        Ok(())
    }

    /// Trusting a warden re-runs the stored policy against the new set, which
    /// is how a policy faulted for an untrusted signer comes back into force
    /// after a key rotation without its rules being discarded.
    pub fn add_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = network::parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        if policy.trusted_wardens().contains(&pubkey) {
            return Ok(());
        }
        let mut wardens = policy.trusted_wardens().clone();
        wardens.insert(pubkey);
        persistence::persist_trusted_wardens(&self.storage, &wardens)?;
        policy.set_trusted_wardens(wardens);
        Self::load_policy_into(&self.storage, &mut policy);
        Ok(())
    }

    /// Untrusting a warden re-runs the stored policy too, so a policy that only
    /// that warden vouched for stops being in force rather than staying in
    /// memory after the signer behind it was withdrawn.
    pub fn remove_trusted_warden(&self, pubkey_hex: String) -> Result<(), KeepMobileError> {
        let pubkey = network::parse_warden_pubkey(&pubkey_hex)?;
        let mut policy = self.policy_write_lock()?;
        if !policy.trusted_wardens().contains(&pubkey) {
            return Ok(());
        }
        let mut wardens = policy.trusted_wardens().clone();
        wardens.remove(&pubkey);
        persistence::persist_trusted_wardens(&self.storage, &wardens)?;
        policy.set_trusted_wardens(wardens);
        Self::load_policy_into(&self.storage, &mut policy);
        Ok(())
    }

    pub fn list_trusted_wardens(&self) -> Result<Vec<String>, KeepMobileError> {
        let policy = self.policy_read_lock()?;
        Ok(policy.trusted_wardens().iter().map(hex::encode).collect())
    }

    pub fn get_certificate_pins(&self) -> Result<Vec<CertificatePin>, KeepMobileError> {
        Ok(persistence::load_cert_pins(&self.storage)?
            .unwrap_or_default()
            .pins()
            .iter()
            .flat_map(|(hostname, hashes)| {
                hashes.iter().map(move |hash| CertificatePin {
                    hostname: hostname.clone(),
                    spki_hash: hex::encode(hash),
                })
            })
            .collect())
    }

    pub fn clear_certificate_pins(&self) -> Result<(), KeepMobileError> {
        {
            let _guard = self
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.storage
                .delete_share_by_key(CERT_PINS_STORAGE_KEY.into())?;
        }
        // A live node holds the pin set it loaded when it was built, and the
        // relay pool reconnects on a timer, so without this a pin edit would not
        // reach it: a cleared pin would stay accepted on the next reconnect and a
        // staged one would not be honored until re-init. Tearing the node down is
        // also the right answer for a removal specifically, since the existing
        // socket was authenticated with a pin the user no longer trusts.
        // Called after the cert-pin guard drops: lock order is
        // node_lifecycle_lock -> cert_pin_lock, so taking them the other way
        // round here would deadlock against `do_initialize`.
        self.invalidate_live_node();
        Ok(())
    }

    pub fn clear_certificate_pin(&self, hostname: String) -> Result<(), KeepMobileError> {
        {
            let _guard = self
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
            pins.remove_pin(&hostname);
            persistence::persist_cert_pins(&self.storage, &pins)?;
        }
        // See `clear_certificate_pins`.
        self.invalidate_live_node();
        Ok(())
    }

    /// Stage an additional accepted SPKI pin for `hostname` (RFC 7469 backup pin)
    /// so the next relay key can be pre-pinned before rotation without a
    /// hard-fail during the key overlap. Additive and de-duplicated, bounded per
    /// host. Adding a trusted pin is a sensitive operator action; the caller MUST
    /// gate it behind explicit user confirmation.
    pub fn stage_certificate_pin(
        &self,
        hostname: String,
        spki_hash: String,
    ) -> Result<(), KeepMobileError> {
        let hostname = normalize_pin_host(&hostname)?;
        let hash = parse_spki_hash(&spki_hash)?;
        {
            let _guard = self
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
            pins.add_pin(hostname, hash);
            persistence::persist_cert_pins(&self.storage, &pins)?;
        }
        // See `clear_certificate_pins`.
        self.invalidate_live_node();
        Ok(())
    }

    /// Remove a single SPKI pin from `hostname`, retiring a rotated-out key while
    /// keeping the host's remaining pins active (unlike `clear_certificate_pin`,
    /// which unpins the whole host). Returns whether a pin was actually removed and
    /// whether the host is now fully unpinned, so the caller can confirm before
    /// leaving a host with no pins (which re-opens trust-on-first-use).
    pub fn remove_certificate_pin(
        &self,
        hostname: String,
        spki_hash: String,
    ) -> Result<CertPinRemovalResult, KeepMobileError> {
        let hostname = normalize_pin_host(&hostname)?;
        let hash = parse_spki_hash(&spki_hash)?;
        let result = {
            let _guard = self
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
            let pin_removed = pins.remove_specific_pin(&hostname, &hash);
            let host_now_unpinned = !pins.is_pinned(&hostname);
            persistence::persist_cert_pins(&self.storage, &pins)?;
            CertPinRemovalResult {
                pin_removed,
                host_now_unpinned,
            }
        };
        // See `clear_certificate_pins`.
        self.invalidate_live_node();
        Ok(result)
    }

    /// List the stored wallet descriptors.
    ///
    /// Every returned `DeviceRegistrationInfo` has its `hmac` field cleared, as
    /// `wallet_register_on_device` does, so no caller of this list receives a
    /// raw registration token. A foreign `SecureStorage` implementation still
    /// holds the token at rest inside the descriptor record it persists, which
    /// is why that trait requires platform secure storage.
    pub fn wallet_descriptor_list(&self) -> Vec<WalletDescriptorInfo> {
        // The exported signature cannot carry the error, so an unreadable index
        // still shows as an empty list. What it no longer does is drive a write:
        // neither this call nor a later save rewrites the index from a partial
        // read. Making the failure visible here needs a fallible signature,
        // which is a binding change for the Android consumer.
        persistence::load_descriptors(&self.storage)
            .map(|load| {
                // Strip the raw registration tokens, as `wallet_register_on_device`
                // does: no list caller needs a value it could log or display, and
                // the generated binding gives the foreign record its own
                // `toString` over every field. The strip cannot move into
                // `stored_to_info`, because `create_backup` reads `hmac` from
                // that same value, and a backup without the tokens restores
                // registrations stripped of the opaque value the device
                // returned, which nothing can regenerate.
                load.loaded
                    .into_iter()
                    .map(|mut d| {
                        for reg in &mut d.device_registrations {
                            reg.hmac = None;
                        }
                        d
                    })
                    .collect()
            })
            .unwrap_or_else(|e| {
                tracing::warn!("Cannot read the descriptor index, reporting no descriptors: {e}");
                Vec::new()
            })
    }

    pub fn wallet_descriptor_export(
        &self,
        group_pubkey: String,
        format: String,
    ) -> Result<String, KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let desc = persistence::load_descriptor(&self.storage, &group_pubkey)?;

        match format.as_str() {
            "sparrow" => {
                let json = serde_json::json!({
                    "descriptor": desc.external_descriptor,
                    "internal_descriptor": desc.internal_descriptor,
                    "network": desc.network,
                });
                serde_json::to_string_pretty(&json)
                    .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })
            }
            "raw" => Ok(desc.external_descriptor),
            _ => Err(KeepMobileError::NotSupported {
                msg: format!("Unknown export format: {format}"),
            }),
        }
    }

    pub fn wallet_descriptor_delete(&self, group_pubkey: String) -> Result<(), KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;
        persistence::delete_descriptor(&self.storage, &group_pubkey)
    }

    /// Register a wallet on a hardware NIP-46 signer and persist the result.
    ///
    /// On success the returned `DeviceRegistrationInfo` has its `hmac` field
    /// cleared so the raw registration token never crosses the UniFFI boundary
    /// into foreign code (Kotlin/Swift), where it could be inadvertently
    /// logged or displayed. The token itself is persisted on the wallet
    /// descriptor in secure storage.
    pub fn wallet_register_on_device(
        &self,
        group_pubkey: String,
        device_uri: String,
        wallet_name: Option<String>,
    ) -> Result<DeviceRegistrationInfo, KeepMobileError> {
        validate_hex_pubkey(&group_pubkey)?;

        let name = wallet_name.unwrap_or_else(|| format!("keep-{}", &group_pubkey[..8]));
        if name.is_empty() {
            return Err(KeepMobileError::InvalidInput {
                msg: "wallet name must not be empty".into(),
            });
        }
        if name.len() > keep_nip46::MAX_WALLET_NAME_LEN {
            return Err(KeepMobileError::InvalidInput {
                msg: format!(
                    "wallet name exceeds {} bytes",
                    keep_nip46::MAX_WALLET_NAME_LEN
                ),
            });
        }

        let desc_initial = persistence::load_descriptor(&self.storage, &group_pubkey)?;

        let multipath = keep_bitcoin::multipath_from_external(&desc_initial.external_descriptor)
            .map_err(|e| KeepMobileError::InvalidInput {
                msg: format!("build multipath descriptor: {e}"),
            })?;

        // The relay list comes from the device URI, so it is attacker-
        // influenceable: pin it before anything is sent. Resolved here, off the
        // async block, so the probe and the live socket get the same proxy.
        let stored_proxy = persistence::load_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();
        let proxy = if stored_proxy.enabled {
            Some(parse_loopback_proxy("127.0.0.1", stored_proxy.port)?)
        } else {
            None
        };
        let (device_signer, uri_relays, uri_secret) = keep_nip46::parse_bunker_url(&device_uri)
            .map_err(|e| KeepMobileError::InvalidInput {
                msg: format!("invalid device URI: {e}"),
            })?;
        // Only the pin read-modify-write needs the lock, so it is released
        // before the session below: that waits on a remote human pressing a
        // button (REGISTER_WALLET_TIMEOUT), and holding `cert_pin_lock` across
        // it would block every cert-pin FFI call, init and bunker start for
        // minutes on a URI naming unreachable relays. `live_pinning` snapshots
        // the pins into its own handle, so a later edit cannot reach this
        // socket whether the lock is held or not. Connect only to what the
        // probe verified: under strict pinning it drops an un-pinned relay
        // from the set rather than failing the whole call.
        let (verified_relays, pinning) = {
            let _cert = self
                .cert_pin_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let relays = self
                .runtime
                .block_on(self.verify_and_pin_relays(&uri_relays, proxy))?;
            (relays, self.live_pinning()?)
        };

        let (signer_hex, hmac_hex, device_info) = self.runtime.block_on(async {
            let client = keep_nip46::Nip46Client::connect_with(
                device_signer,
                verified_relays,
                uri_secret,
                proxy,
                Some(pinning),
            )
            .await
            .map_err(nip46_to_mobile_error)?;
            let signer_hex = hex::encode(client.signer_pubkey().to_bytes());

            let outcome: Result<(Option<String>, Option<keep_nip46::DeviceInfo>), KeepMobileError> =
                async {
                    client.connect().await.map_err(nip46_to_mobile_error)?;
                    // Best-effort: failure must not block registration.
                    let device_info = match client.get_device_info().await {
                        Ok(info) => Some(info),
                        Err(e) => {
                            tracing::warn!("get_device_info failed (best-effort): {e}");
                            None
                        }
                    };
                    if let Some(ref info) = device_info {
                        tracing::warn!(
                            kind = info.kind.as_str(),
                            "device metadata is self-reported by signer and not cryptographically verified",
                        );
                    }
                    let response = client
                        .register_wallet(&name, &multipath)
                        .await
                        .map_err(nip46_to_mobile_error)?;
                    Ok((
                        response.hmac.as_deref().map(|h| hex::encode(h.as_slice())),
                        device_info,
                    ))
                }
                .await;

            client.disconnect().await;
            outcome.map(|(hmac_hex, info)| (signer_hex, hmac_hex, info))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Atomically reload the descriptor under the storage lock so a
        // concurrent register/edit cannot drop our update.
        let persisted = {
            let _guard =
                self.descriptor_write_lock
                    .lock()
                    .map_err(|_| KeepMobileError::StorageError {
                        msg: "descriptor lock poisoned".into(),
                    })?;
            let mut desc = persistence::load_descriptor(&self.storage, &group_pubkey)?;
            let registration = DeviceRegistrationInfo {
                signer_pubkey: signer_hex,
                wallet_name: name,
                hmac: hmac_hex,
                registered_at: now,
                device_kind: device_info.as_ref().map(|d| d.kind.as_str().to_string()),
                fingerprint_hex: device_info
                    .as_ref()
                    .and_then(|d| d.fingerprint_bytes())
                    .map(hex::encode),
                firmware_version: device_info
                    .as_ref()
                    .and_then(|d| d.firmware_version.clone()),
            };
            if let Some(slot) = desc
                .device_registrations
                .iter_mut()
                .find(|r| r.signer_pubkey == registration.signer_pubkey)
            {
                *slot = registration.clone();
            } else {
                desc.device_registrations.push(registration.clone());
            }
            persistence::persist_descriptor(&self.storage, &desc)?;
            registration
        };

        // Strip the raw token before crossing the UniFFI boundary.
        Ok(DeviceRegistrationInfo {
            hmac: None,
            ..persisted
        })
    }

    pub fn wallet_descriptor_set_callbacks(&self, callbacks: Arc<dyn DescriptorCallbacks>) {
        self.runtime.block_on(async {
            *self.descriptor_callbacks.write().await = Some(callbacks);
        });
    }

    pub fn set_health_callbacks(&self, callbacks: Arc<dyn HealthCallbacks>) {
        self.runtime.block_on(async {
            *self.health_callbacks.write().await = Some(callbacks);
        });
    }

    pub fn set_state_callback(&self, callback: Arc<dyn KeepStateCallback>) {
        self.runtime.block_on(async {
            *self.state_callback.write().await = Some(callback);
        });
    }

    pub fn health_check(&self, timeout_secs: u64) -> Result<Vec<u16>, KeepMobileError> {
        if timeout_secs == 0 || timeout_secs > 300 {
            return Err(KeepMobileError::InvalidInput {
                msg: format!("timeout_secs must be between 1 and 300, got {timeout_secs}"),
            });
        }
        self.runtime.block_on(async {
            let (node, group_pubkey, result) = {
                // Clone the handle and drop the guard before the ping. The ping
                // sleeps out its full timeout unconditionally, up to 300s, and
                // tokio's RwLock is write-preferring, so a pending writer also
                // blocks new readers: holding this guard across the ping stalled
                // `invalidate_live_node` and every `node.read()` caller for the
                // whole window, on a healthy group. A share delete, an
                // active-share switch and each cert-pin edit all tear the node
                // down while holding their own locks, so the stall spread to
                // those too. Taking a handle lets the teardown proceed under us,
                // which is what the staleness check after the ping is for.
                let node = {
                    let node_guard = self.node.read().await;
                    Arc::clone(node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?)
                };
                let gp = hex::encode(node.group_pubkey());
                let r = node
                    .health_check(Duration::from_secs(timeout_secs))
                    .await
                    .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
                (node, gp, r)
            };

            // Pongs are only processed by the node's run task, so a teardown
            // during the ping means nothing could answer and every peer comes
            // back unresponsive. Reporting that would persist "all co-signers
            // dead" for a healthy group, which in a multisig pushes a user
            // toward recovery or rotation. Dropping the guard above is what
            // allows the teardown, so the result has to be checked against the
            // node that is live now before it is believed.
            let still_current = match self.node.read().await.as_ref() {
                Some(current) => Arc::ptr_eq(current, &node),
                None => false,
            };
            if !still_current {
                return Err(KeepMobileError::NetworkError {
                    msg: "node was replaced during the health check".into(),
                });
            }

            if let Some(cb) = self.health_callbacks.read().await.as_ref() {
                if let Err(e) = cb.on_health_check_complete(
                    result.responsive.clone(),
                    result.unresponsive.clone(),
                ) {
                    tracing::warn!("Health check callback failed: {e}");
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for (idx, responsive) in result
                .responsive
                .iter()
                .map(|&idx| (idx, true))
                .chain(result.unresponsive.iter().map(|&idx| (idx, false)))
            {
                let existing_created_at =
                    persistence::existing_created_at(&self.storage, &group_pubkey, idx);
                if let Err(e) = persistence::persist_health_status(
                    &self.storage,
                    &KeyHealthStatusInfo {
                        group_pubkey: group_pubkey.clone(),
                        share_index: idx,
                        last_check_timestamp: now,
                        responsive,
                        created_at: existing_created_at.unwrap_or(now),
                        is_stale: false,
                        is_critical: false,
                    },
                ) {
                    tracing::warn!(
                        group_pubkey = %group_pubkey,
                        share_index = %idx,
                        error = %e,
                        "Failed to persist health status"
                    );
                }
            }

            Ok(result.responsive)
        })
    }

    pub fn health_status_list(&self) -> Vec<KeyHealthStatusInfo> {
        persistence::load_health_statuses(&self.storage)
    }

    pub fn wallet_descriptor_propose(
        &self,
        network: String,
        tiers: Vec<RecoveryTierConfig>,
    ) -> Result<String, KeepMobileError> {
        self.wallet_descriptor_propose_with_timeout(network, tiers, None)
    }

    pub fn wallet_descriptor_propose_with_timeout(
        &self,
        network: String,
        tiers: Vec<RecoveryTierConfig>,
        timeout_secs: Option<u64>,
    ) -> Result<String, KeepMobileError> {
        if !keep_frost_net::VALID_NETWORKS.contains(&network.as_str()) {
            return Err(KeepMobileError::NetworkError {
                msg: format!("Invalid network: {network}"),
            });
        }
        if let Some(t) = timeout_secs {
            if t == 0 || t > keep_frost_net::DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS {
                return Err(KeepMobileError::InvalidInput {
                    msg: format!(
                        "timeout_secs must be between 1 and {}, got {t}",
                        keep_frost_net::DESCRIPTOR_SESSION_MAX_TIMEOUT_SECS
                    ),
                });
            }
        }

        self.runtime.block_on(async {
            let session_id = {
                let node_guard = self.node.read().await;
                let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

                let share_info = self
                    .storage
                    .get_share_metadata()
                    .ok_or(KeepMobileError::NotInitialized)?;

                let policy = build_wallet_policy(&tiers, share_info.total_shares)?;

                let (xpub, fingerprint) = node
                    .derive_account_xpub(&network)
                    .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

                validate_xpub_network(&xpub, &network)?;

                node.request_descriptor_with_timeout(
                    policy,
                    &network,
                    &xpub,
                    &fingerprint,
                    timeout_secs,
                )
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?
            };

            self.descriptor_networks
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "Descriptor networks lock poisoned".into(),
                })?
                .insert(session_id, network);

            Ok(hex::encode(session_id))
        })
    }

    pub fn wallet_descriptor_cancel(&self, session_id: String) -> Result<(), KeepMobileError> {
        let id = parse_session_id(&session_id)?;
        clear_descriptor_state(&self.descriptor_networks, &self.pending_contributions, &id);

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            if let Some(node) = node_guard.as_ref() {
                node.cancel_descriptor_session(&id);
            }
        });
        Ok(())
    }

    pub fn wallet_descriptor_approve_contribution(
        &self,
        session_id: String,
    ) -> Result<(), KeepMobileError> {
        let id = parse_session_id(&session_id)?;

        let pending = {
            let guard =
                self.pending_contributions
                    .lock()
                    .map_err(|_| KeepMobileError::StorageError {
                        msg: "Pending contributions lock poisoned".into(),
                    })?;
            guard
                .get(&id)
                .filter(|c| c.created_at.elapsed() < DESCRIPTOR_SESSION_TIMEOUT)
                .cloned()
                .ok_or(KeepMobileError::Timeout)?
        };

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;

            let (xpub, fingerprint) = node
                .derive_account_xpub(&pending.network)
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

            validate_xpub_network(&xpub, &pending.network)?;

            node.contribute_descriptor(id, &pending.initiator_pubkey, &xpub, &fingerprint)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            Ok::<(), KeepMobileError>(())
        })?;

        self.pending_contributions
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Pending contributions lock poisoned".into(),
            })?
            .remove(&id);

        Ok(())
    }

    pub fn wallet_announce_xpubs(
        &self,
        xpubs: Vec<AnnouncedXpubInfo>,
    ) -> Result<(), KeepMobileError> {
        if xpubs.is_empty() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "empty xpub list".into(),
            });
        }
        let announced: Vec<keep_frost_net::AnnouncedXpub> = xpubs
            .into_iter()
            .map(|x| keep_frost_net::AnnouncedXpub {
                xpub: x.xpub,
                fingerprint: x.fingerprint,
                label: x.label,
            })
            .collect();

        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
            node.announce_xpubs(announced)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;
            Ok(())
        })
    }

    pub fn wallet_get_peer_recovery_xpubs(
        &self,
        share_index: u16,
    ) -> Result<Option<Vec<AnnouncedXpubInfo>>, KeepMobileError> {
        self.runtime.block_on(async {
            let node_guard = self.node.read().await;
            let node = node_guard.as_ref().ok_or(KeepMobileError::NotInitialized)?;
            Ok(node.get_peer_recovery_xpubs(share_index).map(|xpubs| {
                xpubs
                    .into_iter()
                    .map(|x| AnnouncedXpubInfo {
                        xpub: x.xpub,
                        fingerprint: x.fingerprint,
                        label: x.label,
                    })
                    .collect()
            }))
        })
    }

    pub fn get_relay_config(
        &self,
        group_pubkey: Option<String>,
    ) -> Result<RelayConfigInfo, KeepMobileError> {
        if let Some(ref pk) = group_pubkey {
            validate_hex_pubkey(pk)?;
        }
        let key = relay_config_key(group_pubkey.as_deref());
        let stored = persistence::load_relay_config(&self.storage, &key)?;
        // No saved config yet: pre-populate the reliable default relay so it
        // shows in the UI and is used immediately, rather than an empty list the
        // user has to fill in. An explicitly-saved empty list is left as-is.
        let config = stored.unwrap_or_else(|| persistence::StoredRelayConfig {
            frost_relays: keep_core::relay::default_frost_relays(),
            bunker_relays: keep_core::relay::default_frost_relays(),
            ..Default::default()
        });
        Ok(RelayConfigInfo {
            frost_relays: config.frost_relays,
            profile_relays: config.profile_relays,
            bunker_relays: config.bunker_relays,
        })
    }

    pub fn save_relay_config(
        &self,
        group_pubkey: Option<String>,
        config: RelayConfigInfo,
    ) -> Result<(), KeepMobileError> {
        if let Some(ref pk) = group_pubkey {
            validate_hex_pubkey(pk)?;
        }
        let normalize_relays =
            |urls: Vec<String>, label: &str| -> Result<Vec<String>, KeepMobileError> {
                if urls.len() > keep_core::relay::MAX_RELAYS {
                    return Err(KeepMobileError::InvalidRelayUrl {
                        msg: format!(
                            "Too many {label} relays (max {})",
                            keep_core::relay::MAX_RELAYS
                        ),
                    });
                }
                let normalized = dedup_stable(
                    urls.iter()
                        .map(|u| keep_core::relay::normalize_relay_url(u)),
                );
                for url in &normalized {
                    network::validate_relay_url(url)?;
                }
                Ok(normalized)
            };
        let key = relay_config_key(group_pubkey.as_deref());
        let _guard = self
            .relay_config_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let existing = match persistence::load_relay_config(&self.storage, &key) {
            Ok(Some(c)) => c,
            Ok(None) => persistence::StoredRelayConfig::default(),
            Err(e) => {
                return Err(KeepMobileError::StorageError {
                    msg: format!("failed to load existing relay config: {e}"),
                });
            }
        };
        let stored = persistence::StoredRelayConfig {
            frost_relays: normalize_relays(config.frost_relays, "FROST")?,
            profile_relays: normalize_relays(config.profile_relays, "profile")?,
            bunker_relays: normalize_relays(config.bunker_relays, "bunker")?,
            peer_policies: existing.peer_policies,
            kfp_v1_peer_policies: existing.kfp_v1_peer_policies,
            bunker_permissions: existing.bunker_permissions,
        };
        persistence::persist_relay_config(&self.storage, &key, &stored)
    }

    pub fn delete_relay_config(&self, group_pubkey: Option<String>) -> Result<(), KeepMobileError> {
        if let Some(ref pk) = group_pubkey {
            validate_hex_pubkey(pk)?;
        }
        let key = relay_config_key(group_pubkey.as_deref());
        // Serialize against save_relay_config / persist_bunker_permissions, which
        // do a read-modify-write on this same key; without the lock a concurrent
        // persist could resurrect the record after the delete.
        let _guard = self
            .relay_config_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.storage
            .delete_share_by_key(key)
            .map_err(|e| KeepMobileError::StorageError {
                msg: format!("failed to delete relay config: {e}"),
            })?;
        Ok(())
    }

    pub fn get_kill_switch(&self) -> Result<bool, KeepMobileError> {
        persistence::load_kill_switch(&self.storage, KILL_SWITCH_STORAGE_KEY)
    }

    pub fn set_kill_switch(&self, enabled: bool) -> Result<(), KeepMobileError> {
        persistence::persist_kill_switch(&self.storage, KILL_SWITCH_STORAGE_KEY, enabled)
    }

    pub fn get_proxy_config(&self) -> Result<ProxyConfigInfo, KeepMobileError> {
        let stored = persistence::load_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY)?;
        let config = stored.unwrap_or_default();
        Ok(ProxyConfigInfo {
            enabled: config.enabled,
            port: config.port,
        })
    }

    pub fn save_proxy_config(&self, config: ProxyConfigInfo) -> Result<(), KeepMobileError> {
        if config.port == 0 {
            return Err(KeepMobileError::InvalidInput {
                msg: "proxy port must be non-zero".into(),
            });
        }
        let stored = persistence::StoredProxyConfig {
            enabled: config.enabled,
            port: config.port,
        };
        persistence::persist_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY, &stored)
    }

    /// Whether strict certificate pinning is enabled. When true, connecting to a
    /// relay that has no pre-provisioned pin is rejected (fail-closed) instead of
    /// trusted-on-first-use, closing the first-connection MitM window that plain
    /// TOFU leaves open. Opt-in and disabled by default: enable it only after
    /// staging each relay's pin via `stage_certificate_pin`, or new connections
    /// to un-pinned relays will fail until their pins are provisioned.
    pub fn get_strict_cert_pinning(&self) -> Result<bool, KeepMobileError> {
        Ok(
            persistence::load_strict_pin_config(&self.storage, STRICT_PIN_CONFIG_STORAGE_KEY)?
                .unwrap_or_default()
                .enabled,
        )
    }

    /// Enable or disable strict certificate pinning (see `get_strict_cert_pinning`).
    ///
    /// A live node captured the old setting when it was built, so it is torn
    /// down here rather than left running with the previous policy until the
    /// next re-init.
    pub fn set_strict_cert_pinning(&self, enabled: bool) -> Result<(), KeepMobileError> {
        let config = persistence::StoredStrictPinConfig { enabled };
        persistence::persist_strict_pin_config(
            &self.storage,
            STRICT_PIN_CONFIG_STORAGE_KEY,
            &config,
        )?;
        self.invalidate_live_node();
        Ok(())
    }

    pub fn get_bunker_config(&self) -> Result<BunkerConfigInfo, KeepMobileError> {
        let stored = persistence::load_bunker_config(&self.storage, BUNKER_CONFIG_STORAGE_KEY)?;
        let config = stored.unwrap_or_default();
        Ok(BunkerConfigInfo {
            enabled: config.enabled,
            authorized_clients: config.authorized_clients,
        })
    }

    pub fn save_bunker_config(&self, config: BunkerConfigInfo) -> Result<(), KeepMobileError> {
        // Preserve the persisted transport key + connect secret so toggling the
        // bunker off/on (or any other config save) does not rotate the bunker://
        // URL out from under already-paired clients. The whole read-modify-write
        // runs under bunker_config_lock so a save that loaded a stale snapshot
        // (transport_secret: None) cannot clobber keys freshly generated and
        // persisted by a concurrent load_or_create_bunker_keys.
        let _guard = self
            .bunker_config_lock
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "bunker config lock poisoned".into(),
            })?;
        let existing = persistence::load_bunker_config(&self.storage, BUNKER_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();
        let stored = persistence::StoredBunkerConfig {
            enabled: config.enabled,
            authorized_clients: config.authorized_clients,
            transport_secret: existing.transport_secret,
            connect_secret: existing.connect_secret,
        };
        persistence::persist_bunker_config(&self.storage, BUNKER_CONFIG_STORAGE_KEY, &stored)
    }

    pub fn create_backup(&self, passphrase: String) -> Result<Vec<u8>, KeepMobileError> {
        use keep_core::backup::{self, BackupConfig, BackupShare as CoreBackupShare};
        let passphrase = Zeroizing::new(passphrase);

        if passphrase.chars().count() < backup::MIN_PASSPHRASE_LEN {
            return Err(KeepMobileError::InvalidInput {
                msg: format!(
                    "Passphrase must be at least {} characters",
                    backup::MIN_PASSPHRASE_LEN
                ),
            });
        }

        let all_share_meta = self.storage.list_all_shares();
        let mut backup_shares = Vec::with_capacity(all_share_meta.len());

        for meta in &all_share_meta {
            let group_hex = hex::encode(&meta.group_pubkey);
            let data = self.storage.load_share_by_key(group_hex.clone())?;
            let stored: StoredShareData =
                serde_json::from_slice(&data).map_err(|e| KeepMobileError::StorageError {
                    msg: format!("Failed to deserialize share data: {e}"),
                })?;
            let share_meta: keep_core::frost::ShareMetadata =
                serde_json::from_str(&stored.metadata_json).map_err(|e| {
                    KeepMobileError::StorageError {
                        msg: format!("Failed to deserialize share metadata: {e}"),
                    }
                })?;
            backup_shares.push(CoreBackupShare {
                identifier: share_meta.identifier,
                threshold: share_meta.threshold,
                total_shares: share_meta.total_shares,
                group_pubkey: hex::encode(share_meta.group_pubkey),
                name: share_meta.name.clone(),
                created_at: share_meta.created_at,
                last_used: share_meta.last_used,
                sign_count: share_meta.sign_count,
                did_backup: share_meta.did_backup,
                key_package: hex::encode(&stored.key_package_bytes),
                pubkey_package: hex::encode(&stored.pubkey_package_bytes),
                ciphersuite: stored.ciphersuite,
                group_subkey_secret: share_meta.group_subkey_secret.map(hex::encode),
            });
        }

        // Reported, not refused. A backup missing a descriptor is a real hazard,
        // because the user restores from it elsewhere and then wipes the device
        // trusting it, but refusing the whole backup denies the shares too, and
        // the shares are the irreplaceable part while a descriptor is public
        // xpub data. Refusing also has no exit on the shipped consumer: the
        // error text is replaced by a static string and the one
        // `wallet_descriptor_delete` call site can only pass a group the list
        // returned, which by construction excludes the entry that is blocking.
        // So a single unreadable record would permanently deny every backup of
        // the share material behind a generic failure. Surfacing this properly
        // needs a channel the exported signature does not have; `unreadable` is
        // the seam for it.
        let load = persistence::load_descriptors(&self.storage)?;
        if !load.unreadable.is_empty() {
            tracing::warn!(
                unreadable = %load.unreadable.join(", "),
                "backup omits descriptors whose records could not be read"
            );
        }
        let descriptors = load.loaded;
        let mut core_descriptors = Vec::with_capacity(descriptors.len());
        for d in &descriptors {
            let bytes = decode_hex(&d.group_pubkey, "descriptor group_pubkey")?;
            let group_pubkey = bytes_to_32(&bytes, "descriptor group_pubkey")?;
            let mut device_registrations = Vec::with_capacity(d.device_registrations.len());
            for reg in &d.device_registrations {
                let signer_bytes =
                    decode_hex(&reg.signer_pubkey, "device_registration signer_pubkey")?;
                let signer_pubkey =
                    bytes_to_32(&signer_bytes, "device_registration signer_pubkey")?;
                let hmac = match reg.hmac.as_deref() {
                    Some(h) => {
                        if !persistence::is_valid_hmac_hex(h) {
                            return Err(KeepMobileError::BackupError {
                                msg: "device_registration hmac has invalid hex length or format"
                                    .into(),
                            });
                        }
                        Some(Zeroizing::new(decode_hex(h, "device_registration hmac")?))
                    }
                    None => None,
                };
                let fingerprint = match reg.fingerprint_hex.as_deref() {
                    Some(s) => {
                        let bytes = decode_hex(s, "device_registration.fingerprint_hex")?;
                        if bytes.len() != 4 {
                            return Err(KeepMobileError::BackupError {
                                msg: format!(
                                    "device_registration.fingerprint_hex must decode to 4 bytes, got {}",
                                    bytes.len()
                                ),
                            });
                        }
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(&bytes);
                        if arr == [0u8; 4] {
                            return Err(KeepMobileError::BackupError {
                                msg: "device_registration.fingerprint_hex 00000000 is reserved by BIP32 for 'no parent'".into(),
                            });
                        }
                        Some(arr)
                    }
                    None => None,
                };
                if let Some(ref k) = reg.device_kind {
                    keep_nip46::validate_metadata_field(
                        "device_registration.device_kind",
                        k,
                        0,
                        keep_nip46::MAX_DEVICE_KIND_LEN,
                    )
                    .map_err(|e| KeepMobileError::BackupError { msg: e.to_string() })?;
                }
                if let Some(ref fw) = reg.firmware_version {
                    keep_nip46::validate_metadata_field(
                        "device_registration.firmware_version",
                        fw,
                        0,
                        keep_nip46::MAX_FIRMWARE_VERSION_LEN,
                    )
                    .map_err(|e| KeepMobileError::BackupError { msg: e.to_string() })?;
                }
                device_registrations.push(keep_core::DeviceRegistration {
                    signer_pubkey,
                    wallet_name: reg.wallet_name.clone(),
                    hmac,
                    registered_at: reg.registered_at,
                    device_kind: reg.device_kind.clone(),
                    fingerprint,
                    firmware_version: reg.firmware_version.clone(),
                });
            }
            let policy_hash = match d.policy_hash_hex.as_deref() {
                Some(h) => {
                    let bytes = decode_hex(h, "descriptor policy_hash")?;
                    bytes_to_32(&bytes, "descriptor policy_hash")?
                }
                None => [0u8; 32],
            };
            if d.version == 0 {
                return Err(KeepMobileError::BackupError {
                    msg: "descriptor version must be >= 1".into(),
                });
            }
            let previous_descriptor_hash = match d.previous_descriptor_hash_hex.as_deref() {
                Some(h) => {
                    let bytes = decode_hex(h, "descriptor previous_descriptor_hash")?;
                    Some(bytes_to_32(&bytes, "descriptor previous_descriptor_hash")?)
                }
                None => None,
            };
            let policy = match d.policy_json.as_deref() {
                Some(s) => Some(serde_json::from_str::<serde_json::Value>(s).map_err(|e| {
                    KeepMobileError::BackupError {
                        msg: format!("descriptor policy_json is not valid JSON: {e}"),
                    }
                })?),
                None => None,
            };
            core_descriptors.push(keep_core::wallet::WalletDescriptor {
                group_pubkey,
                external_descriptor: d.external_descriptor.clone(),
                internal_descriptor: d.internal_descriptor.clone(),
                network: d.network.clone(),
                created_at: d.created_at,
                device_registrations,
                policy_hash,
                version: d.version,
                previous_descriptor_hash,
                policy,
            });
        }

        let mut relay_configs = Vec::new();
        for meta in &all_share_meta {
            let group_hex = hex::encode(&meta.group_pubkey);
            let key = relay_config_key(Some(&group_hex));
            if let Ok(Some(stored)) = persistence::load_relay_config(&self.storage, &key) {
                let group_pubkey = bytes_to_32(&meta.group_pubkey, "relay group_pubkey")?;
                relay_configs.push(keep_core::relay::RelayConfig {
                    group_pubkey,
                    frost_relays: stored.frost_relays,
                    profile_relays: stored.profile_relays,
                    bunker_relays: stored.bunker_relays,
                    peer_policies: stored.peer_policies,
                    kfp_v1_peer_policies: stored.kfp_v1_peer_policies,
                    bunker_permissions: stored.bunker_permissions,
                    auto_approve_kinds: Vec::new(),
                });
            }
        }

        let health_infos = persistence::load_health_statuses(&self.storage);
        let mut core_health = Vec::with_capacity(health_infos.len());
        for h in &health_infos {
            let bytes = decode_hex(&h.group_pubkey, "health group_pubkey")?;
            let group_pubkey = bytes_to_32(&bytes, "health group_pubkey")?;
            core_health.push(keep_core::wallet::KeyHealthStatus {
                group_pubkey,
                share_index: h.share_index,
                last_check_timestamp: h.last_check_timestamp,
                responsive: h.responsive,
                created_at: Some(h.created_at),
            });
        }

        let proxy = persistence::load_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();
        let core_proxy = if proxy.enabled {
            Some(keep_core::storage::ProxyConfig {
                enabled: proxy.enabled,
                port: proxy.port,
            })
        } else {
            None
        };

        let kill_switch = persistence::load_kill_switch(&self.storage, KILL_SWITCH_STORAGE_KEY)?;

        let config = BackupConfig {
            kill_switch,
            proxy: core_proxy,
        };

        backup::create_backup_from_data(
            Vec::new(),
            backup_shares,
            core_descriptors,
            relay_configs,
            core_health,
            config,
            Vec::new(),
            &passphrase,
        )
        .map_err(|e| KeepMobileError::BackupError { msg: e.to_string() })
    }

    pub fn verify_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<BackupInfo, KeepMobileError> {
        let file_size = data.len();
        let decrypted = decrypt_backup_data(&data, &passphrase)?;
        Ok(backup_info(&decrypted, file_size))
    }

    /// Restore a backup into the current mobile storage.
    ///
    /// Persistence is **not atomic**: shares, descriptors, relay configs, and
    /// health statuses are written sequentially via `SecureStorage`. A failure
    /// partway through may leave partial state. Callers should treat a
    /// returned error as "possibly partially restored" and retry or clean up.
    pub fn restore_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<BackupInfo, KeepMobileError> {
        let file_size = data.len();
        let decrypted = decrypt_backup_data(&data, &passphrase)?;
        let info = backup_info(&decrypted, file_size);

        let mut first_group_hex: Option<String> = None;

        let mut prepared_shares: Vec<(String, Vec<u8>, ShareMetadataInfo)> = Vec::new();
        let mut prepared_keys: Vec<(String, Vec<u8>, ShareMetadataInfo)> = Vec::new();
        let mut prepared_descriptors: Vec<WalletDescriptorInfo> = Vec::new();
        let mut prepared_relays: Vec<(String, persistence::StoredRelayConfig)> = Vec::new();
        let mut prepared_health: Vec<KeyHealthStatusInfo> = Vec::new();

        for bs in &decrypted.shares {
            if bs.ciphersuite != keep_core::frost::Ciphersuite::Secp256k1Tr {
                tracing::warn!(
                    name = %bs.name,
                    "skipping non-secp256k1 share during restore: unsupported on mobile"
                );
                continue;
            }
            let mut key_package_bytes = Zeroizing::new(decode_hex(&bs.key_package, "key_package")?);
            let pubkey_package_bytes = decode_hex(&bs.pubkey_package, "pubkey_package")?;
            let group_pubkey_bytes = decode_hex(&bs.group_pubkey, "group_pubkey")?;
            let group_pubkey_32 = bytes_to_32(&group_pubkey_bytes, "group pubkey")?;

            let group_hex = bs.group_pubkey.to_ascii_lowercase();
            if first_group_hex.is_none() {
                first_group_hex = Some(group_hex.clone());
            }

            let metadata = ShareMetadataInfo {
                name: bs.name.clone(),
                identifier: bs.identifier,
                threshold: bs.threshold,
                total_shares: bs.total_shares,
                group_pubkey: group_pubkey_bytes,
                // Preserve what the backup recorded rather than asserting it.
                // Marking a share backed up when it was not suppresses the
                // prompt telling the user to back it up, and keep-core's own
                // restore already carries the recorded value through.
                did_backup: bs.did_backup,
            };

            let share_meta = keep_core::frost::ShareMetadata {
                identifier: bs.identifier,
                threshold: bs.threshold,
                total_shares: bs.total_shares,
                group_pubkey: group_pubkey_32,
                name: bs.name.clone(),
                created_at: bs.created_at,
                last_used: bs.last_used,
                sign_count: bs.sign_count,
                did_backup: bs.did_backup,
                group_subkey_secret: bs
                    .group_subkey_secret
                    .as_deref()
                    .map(|s| {
                        bytes_to_32(
                            &decode_hex(s, "group_subkey_secret")?,
                            "group subkey secret",
                        )
                    })
                    .transpose()?,
            };

            let stored = StoredShareData {
                metadata_json: serde_json::to_string(&share_meta)
                    .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?,
                key_package_bytes: std::mem::replace(
                    &mut key_package_bytes,
                    Zeroizing::new(Vec::new()),
                ),
                pubkey_package_bytes,
                plaintext_mnemonic: None,
                ciphersuite: bs.ciphersuite,
            };

            let serialized = serde_json::to_vec(&stored)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

            prepared_shares.push((group_hex, serialized, metadata));
        }

        for bk in &decrypted.keys {
            let secret_bytes = Zeroizing::new(decode_hex(&bk.secret, "key secret")?);

            let (key_package, pubkey_package, vk_bytes) = Self::build_nsec_packages(&secret_bytes)
                .map_err(|e| KeepMobileError::BackupError {
                    msg: format!("nsec conversion: {e}"),
                })?;

            let (metadata_info, stored) = Self::build_nsec_share_data(
                key_package,
                pubkey_package,
                vk_bytes,
                bk.name.clone(),
                None,
                // Keys carry no recorded flag to preserve, so this is a choice
                // rather than a restoration. It matches `import_nsec`, and it is
                // the safe direction: the flag tracks whether the user has saved
                // this key's seed words, which restoring a vault file does not
                // establish. Claiming otherwise hides the prompt to save them.
                false,
            )
            .map_err(|e| KeepMobileError::BackupError {
                msg: format!("nsec share data: {e}"),
            })?;

            let group_hex = hex::encode(&metadata_info.group_pubkey);
            if first_group_hex.is_none() {
                first_group_hex = Some(group_hex.clone());
            }

            let serialized = serde_json::to_vec(&stored)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

            prepared_keys.push((group_hex, serialized, metadata_info));
        }

        for wd in &decrypted.wallet_descriptors {
            let policy_hash_hex = if wd.policy_hash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(wd.policy_hash))
            };
            let policy_json =
                match wd.policy.as_ref() {
                    Some(v) => Some(serde_json::to_string(v).map_err(|e| {
                        KeepMobileError::BackupError {
                            msg: format!("failed to serialize descriptor policy: {e}"),
                        }
                    })?),
                    None => None,
                };
            prepared_descriptors.push(WalletDescriptorInfo {
                group_pubkey: hex::encode(wd.group_pubkey),
                external_descriptor: wd.external_descriptor.clone(),
                internal_descriptor: wd.internal_descriptor.clone(),
                network: wd.network.clone(),
                created_at: wd.created_at,
                device_registrations: wd
                    .device_registrations
                    .iter()
                    .map(|r| DeviceRegistrationInfo {
                        signer_pubkey: hex::encode(r.signer_pubkey),
                        wallet_name: r.wallet_name.clone(),
                        hmac: r.hmac.as_deref().map(hex::encode),
                        registered_at: r.registered_at,
                        device_kind: r.device_kind.clone(),
                        fingerprint_hex: r.fingerprint.map(hex::encode),
                        firmware_version: r.firmware_version.clone(),
                    })
                    .collect(),
                policy_hash_hex,
                version: wd.version,
                previous_descriptor_hash_hex: wd.previous_descriptor_hash.map(hex::encode),
                policy_json,
            });
        }

        for rc in &decrypted.relay_configs {
            let group_hex = hex::encode(rc.group_pubkey);
            let stored_relay = persistence::StoredRelayConfig {
                frost_relays: rc.frost_relays.clone(),
                profile_relays: rc.profile_relays.clone(),
                bunker_relays: rc.bunker_relays.clone(),
                peer_policies: rc.peer_policies.clone(),
                kfp_v1_peer_policies: rc.kfp_v1_peer_policies.clone(),
                bunker_permissions: rc.bunker_permissions.clone(),
            };
            prepared_relays.push((group_hex, stored_relay));
        }

        for hs in &decrypted.health_statuses {
            prepared_health.push(KeyHealthStatusInfo {
                group_pubkey: hex::encode(hs.group_pubkey),
                share_index: hs.share_index,
                last_check_timestamp: hs.last_check_timestamp,
                responsive: hs.responsive,
                created_at: hs.created_at.unwrap_or(hs.last_check_timestamp),
                is_stale: false,
                is_critical: false,
            });
        }

        for (group_hex, _, _) in prepared_shares.iter().chain(prepared_keys.iter()) {
            if self.storage.load_share_by_key(group_hex.clone()).is_ok() {
                return Err(KeepMobileError::BackupError {
                    msg: format!("key/share already exists for group {group_hex}"),
                });
            }
        }

        // Descriptors before the shares and keys. Only the share and key writes
        // are covered by the duplicate guard above, so a failure after them is
        // terminal: the retry sees the shares it wrote and refuses. Running the
        // descriptor writes first means a descriptor failure leaves nothing
        // behind, and `persist_descriptor` is idempotent for a group already in
        // the index, so the retry completes instead of being rejected.
        for desc_info in prepared_descriptors {
            persistence::persist_descriptor(&self.storage, &desc_info)?;
        }

        for (group_hex, serialized, metadata) in prepared_shares {
            self.storage
                .store_share_by_key(group_hex, serialized, metadata)?;
        }

        for (group_hex, serialized, metadata_info) in prepared_keys {
            self.storage
                .store_share_by_key(group_hex, serialized, metadata_info)?;
        }

        for (group_hex, stored_relay) in prepared_relays {
            let key = relay_config_key(Some(&group_hex));
            persistence::persist_relay_config(&self.storage, &key, &stored_relay)?;
        }

        for health_info in prepared_health {
            persistence::persist_health_status(&self.storage, &health_info)?;
        }

        if let Some(proxy) = &decrypted.config.proxy {
            let stored_proxy = persistence::StoredProxyConfig {
                enabled: proxy.enabled,
                port: proxy.port,
            };
            persistence::persist_proxy_config(
                &self.storage,
                PROXY_CONFIG_STORAGE_KEY,
                &stored_proxy,
            )?;
        }

        persistence::persist_kill_switch(
            &self.storage,
            KILL_SWITCH_STORAGE_KEY,
            decrypted.config.kill_switch,
        )?;

        if self.storage.get_active_share_key().is_none() {
            if let Some(group_hex) = first_group_hex {
                let _ = self.storage.set_active_share_key(Some(group_hex));
            }
        }

        Ok(info)
    }
}

fn decrypt_backup_data(
    data: &[u8],
    passphrase: &str,
) -> Result<keep_core::backup::DecryptedBackup, KeepMobileError> {
    let passphrase = Zeroizing::new(passphrase.to_owned());
    if data.len() > keep_core::backup::MAX_BACKUP_SIZE {
        return Err(KeepMobileError::BackupError {
            msg: format!(
                "backup too large ({} bytes, max {})",
                data.len(),
                keep_core::backup::MAX_BACKUP_SIZE
            ),
        });
    }
    keep_core::backup::decrypt_backup(data, &passphrase)
        .map_err(|e| KeepMobileError::BackupError { msg: e.to_string() })
}

fn backup_info(decrypted: &keep_core::backup::DecryptedBackup, file_size: usize) -> BackupInfo {
    BackupInfo {
        key_count: decrypted.keys.len() as u32,
        share_count: decrypted.shares.len() as u32,
        descriptor_count: decrypted.wallet_descriptors.len() as u32,
        created_at: decrypted.created_at.clone(),
        file_size: file_size as u64,
    }
}

fn decode_hex(hex_str: &str, label: &str) -> Result<Vec<u8>, KeepMobileError> {
    hex::decode(hex_str).map_err(|e| KeepMobileError::BackupError {
        msg: format!("hex decode {label}: {e}"),
    })
}

fn nip46_to_mobile_error(e: keep_core::error::KeepError) -> KeepMobileError {
    use keep_core::error::{KeepError, NetworkError};
    match e {
        KeepError::InvalidInput(msg) => KeepMobileError::InvalidInput { msg },
        KeepError::UserRejected => KeepMobileError::InvalidInput {
            msg: "request rejected".into(),
        },
        KeepError::RateLimited(_) => KeepMobileError::RateLimited,
        KeepError::CapacityExceeded(_) => KeepMobileError::RateLimited,
        KeepError::NetworkErr(NetworkError::Timeout { .. }) => KeepMobileError::Timeout,
        KeepError::NetworkErr(e) => KeepMobileError::NetworkError { msg: e.to_string() },
        KeepError::StorageErr(e) => KeepMobileError::StorageError { msg: e.to_string() },
        KeepError::CryptoErr(e) => KeepMobileError::FrostError { msg: e.to_string() },
        KeepError::Encryption(msg) => KeepMobileError::EncryptionError { msg },
        KeepError::Runtime(msg) => KeepMobileError::NotSupported { msg },
        other => KeepMobileError::NetworkError {
            msg: other.to_string(),
        },
    }
}

fn bytes_to_32(bytes: &[u8], label: &str) -> Result<[u8; 32], KeepMobileError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| KeepMobileError::BackupError {
        msg: format!("invalid {label} length: {} (expected 32)", bytes.len()),
    })
}

/// Parse a hex-encoded SHA-256 SPKI pin (64 hex chars) into its 32 bytes.
fn parse_spki_hash(spki_hash: &str) -> Result<[u8; 32], KeepMobileError> {
    bytes_to_32(&decode_hex(spki_hash, "SPKI hash")?, "SPKI hash")
}

/// Canonicalize an operator-supplied relay host to the exact key certificate pins
/// are stored and verified under, rejecting input that cannot be parsed to a host
/// (so a pin can never be stored under a scheme/port/case-variant that never
/// matches at verification time).
fn normalize_pin_host(hostname: &str) -> Result<String, KeepMobileError> {
    keep_frost_net::normalize_pin_hostname(hostname).ok_or_else(|| {
        KeepMobileError::InvalidRelayUrl {
            msg: "invalid relay hostname for certificate pin".into(),
        }
    })
}

/// Whether `relay` is a `wss` URL whose host has no provisioned certificate pin.
/// Uses the same host key as the verified-relay filter so strict mode skips
/// exactly the relays that filter would exclude. Non-`wss` or unparseable relays
/// are left to the normal verification path.
fn wss_relay_lacks_pin(relay: &str, pins: &keep_frost_net::CertificatePinSet) -> bool {
    match url::Url::parse(relay) {
        Ok(u) if u.scheme() == "wss" => u.host_str().map(|h| !pins.is_pinned(h)).unwrap_or(true),
        _ => false,
    }
}

fn relay_config_key(group_pubkey: Option<&str>) -> String {
    match group_pubkey {
        Some(pk) => {
            let canonical = pk.to_ascii_lowercase();
            format!("{RELAY_CONFIG_KEY_PREFIX}{canonical}")
        }
        None => RELAY_CONFIG_GLOBAL_KEY.into(),
    }
}

fn dedup_stable(iter: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    iter.filter(|s| seen.insert(s.clone())).collect()
}

fn clear_descriptor_state(
    nets: &std::sync::Mutex<HashMap<[u8; 32], String>>,
    pending: &std::sync::Mutex<HashMap<[u8; 32], PendingContribution>>,
    session_id: &[u8; 32],
) {
    if let Ok(mut n) = nets.lock() {
        n.remove(session_id);
    }
    if let Ok(mut p) = pending.lock() {
        p.remove(session_id);
    }
}

fn parse_session_id(hex: &str) -> Result<[u8; 32], KeepMobileError> {
    let bytes = hex::decode(hex).map_err(|_| KeepMobileError::InvalidSession)?;
    bytes
        .try_into()
        .map_err(|_| KeepMobileError::InvalidSession)
}

fn validate_xpub_network(xpub: &str, network: &str) -> Result<(), KeepMobileError> {
    let expected_prefix = match network {
        "bitcoin" => "xpub",
        "testnet" | "signet" | "regtest" => "tpub",
        _ => return Ok(()),
    };
    if !xpub.starts_with(expected_prefix) {
        return Err(KeepMobileError::FrostError {
            msg: format!("xpub prefix mismatch: expected {expected_prefix}* for network {network}"),
        });
    }
    Ok(())
}

fn build_wallet_policy(
    tiers: &[RecoveryTierConfig],
    total_shares: u16,
) -> Result<keep_frost_net::WalletPolicy, KeepMobileError> {
    use keep_frost_net::{KeySlot, PolicyTier, WalletPolicy};

    if tiers.is_empty() {
        return Err(KeepMobileError::FrostError {
            msg: "At least one recovery tier is required".into(),
        });
    }

    for tier in tiers {
        if tier.threshold == 0 {
            return Err(KeepMobileError::FrostError {
                msg: "Recovery tier threshold must be > 0".into(),
            });
        }
        if tier.threshold > u32::from(total_shares) {
            return Err(KeepMobileError::FrostError {
                msg: format!(
                    "Recovery tier threshold {} exceeds total shares {}",
                    tier.threshold, total_shares
                ),
            });
        }
        if tier.timelock_months == 0 {
            return Err(KeepMobileError::FrostError {
                msg: "Recovery tier timelock_months must be > 0".into(),
            });
        }
    }

    let recovery_tiers = tiers
        .iter()
        .map(|tier| {
            let key_slots = (1..=total_shares)
                .map(|i| KeySlot::Participant { share_index: i })
                .collect();
            PolicyTier {
                threshold: tier.threshold,
                key_slots,
                timelock_months: tier.timelock_months,
            }
        })
        .collect();

    Ok(WalletPolicy {
        recovery_tiers,
        version: keep_core::wallet::INITIAL_DESCRIPTOR_VERSION,
    })
}

impl KeepMobile {
    /// Load the persisted NIP-46 bunker permission grants from the global relay
    /// config, returning them ready to seed `ServerConfig::pre_grants` so
    /// remembered grants survive a bunker restart.
    pub(crate) fn load_bunker_permissions(&self) -> Vec<keep_core::relay::StoredBunkerPermission> {
        let key = relay_config_key(None);
        match persistence::load_relay_config(&self.storage, &key) {
            Ok(Some(c)) => c.bunker_permissions,
            Ok(None) => Vec::new(),
            // A real load error (decrypt/deserialize failure, corruption, or
            // tampering) is NOT the same as "no config yet". Seeding empty
            // grants is fail-safe (more prompting), but the next grant's persist
            // would then overwrite the durable store and erase the remembered
            // grants for good, so surface the error loudly rather than swallow it.
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load persisted bunker permissions; starting with \
                     none (a subsequent grant will overwrite the durable store)"
                );
                Vec::new()
            }
        }
    }

    /// Replace the persisted NIP-46 bunker permission grants with `grants`,
    /// preserving the relay lists. Called from the engine's `persist_permissions`
    /// callback after every grant write or revoke, so the durable store mirrors
    /// the in-memory engine (the single source of truth).
    pub(crate) fn persist_bunker_permissions(
        &self,
        grants: Vec<keep_core::relay::StoredBunkerPermission>,
    ) -> Result<(), KeepMobileError> {
        let key = relay_config_key(None);
        let _guard = self
            .relay_config_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut stored = match persistence::load_relay_config(&self.storage, &key) {
            Ok(Some(c)) => c,
            Ok(None) => persistence::StoredRelayConfig::default(),
            Err(e) => {
                return Err(KeepMobileError::StorageError {
                    msg: format!("failed to load existing relay config: {e}"),
                });
            }
        };
        stored.bunker_permissions = grants;
        persistence::persist_relay_config(&self.storage, &key, &stored)
    }

    /// Abort any prior node's tasks and drop their pending sign requests before a
    /// replacement node starts. Must run before the new node's listener/run tasks
    /// spawn: clearing up front means the clear cannot race the fresh session,
    /// whose requests can only be enqueued once those tasks are live, so a
    /// replacement never loses the new session's requests. A first init has no
    /// prior tasks, so pending is left untouched. Mirrors invalidate_live_node
    /// minus nulling the node, which do_initialize overwrites immediately after.
    async fn retire_prior_node_tasks(&self) {
        let replaced_prior_node = {
            let mut tasks = self
                .node_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let had_prior = !tasks.is_empty();
            for handle in tasks.drain(..) {
                handle.abort();
            }
            had_prior
        };

        if replaced_prior_node {
            self.pending_requests.lock().await.clear();
        }
    }

    /// Pin configuration for the live relay sockets.
    ///
    /// The stored pin set is handed to the transport, which only ever reads it:
    /// enforcing the pin on the live handshake is the transport's job, while
    /// learning one on first use stays with `verify_and_pin_relays` below,
    /// which runs under `cert_pin_lock` and is allowed to touch storage. Since
    /// the handshake records nothing, there is nothing to write back after
    /// connecting, and so no way for a connection to clobber a pin staged or
    /// cleared through the FFI while it was coming up.
    fn live_pinning(&self) -> Result<keep_frost_net::TlsPinning, KeepMobileError> {
        let require_pinned =
            persistence::load_strict_pin_config(&self.storage, STRICT_PIN_CONFIG_STORAGE_KEY)?
                .unwrap_or_default()
                .enabled;
        let pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
        Ok(keep_frost_net::TlsPinning::new(
            Arc::new(std::sync::Mutex::new(pins)),
            require_pinned,
        ))
    }

    /// Verify each relay's TLS certificate against the stored pins (trust-on-
    /// first-use, or strict when configured), persist any newly learned pins,
    /// and return the subset that passed. Fails closed if none pass.
    ///
    /// The caller must hold `cert_pin_lock` across this call so the read-modify-
    /// write of the persisted pin set cannot lose an update to a concurrent
    /// stage/remove/clear FFI call.
    /// `proxy` MUST be the address the live sockets get: the probe is its own
    /// TCP connection, so one that dials direct reveals the host address on
    /// every connect even when the data socket is proxied.
    async fn verify_and_pin_relays(
        &self,
        relays: &[String],
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<Vec<String>, KeepMobileError> {
        // Opt-in strict pinning: when enabled, an un-pinned relay is not
        // trusted-on-first-use; it is skipped (see the per-relay handling
        // below) rather than pinned. Disabled by default.
        let require_pinned =
            persistence::load_strict_pin_config(&self.storage, STRICT_PIN_CONFIG_STORAGE_KEY)?
                .unwrap_or_default()
                .enabled;
        let mut pins = persistence::load_cert_pins(&self.storage)?.unwrap_or_default();
        let mut pins_changed = false;
        for relay in relays {
            // Strict mode: skip an un-pinned relay rather than aborting for the
            // whole set. It is excluded from `verified_relays` below, and the
            // empty-set check there fails closed if none are pinned. A pinned
            // relay presenting a mismatched cert stays a fatal MitM.
            if require_pinned && wss_relay_lacks_pin(relay, &pins) {
                tracing::warn!(
                    relay = %relay,
                    "strict pinning: skipping relay with no provisioned pin"
                );
                continue;
            }
            match keep_frost_net::verify_relay_certificate(relay, &pins, require_pinned, proxy)
                .await
            {
                Ok((_hash, new_pin)) => {
                    if let Some((hostname, hash)) = new_pin {
                        if !pins.is_pinned(&hostname) {
                            pins.add_pin(hostname, hash);
                            pins_changed = true;
                        }
                    }
                }
                Err(
                    e @ (keep_frost_net::FrostNetError::CertificatePinMismatch { .. }
                    | keep_frost_net::FrostNetError::CertificatePinMissing { .. }),
                ) => {
                    // Fail closed on both a changed pin and, under strict mode,
                    // an un-provisioned relay; do not silently skip.
                    return Err(e.into());
                }
                Err(e) => {
                    tracing::warn!(relay = %relay, error = %e, "TLS certificate verification failed, skipping relay");
                }
            }
        }
        if pins_changed {
            persistence::persist_cert_pins(&self.storage, &pins)?;
        }

        let verified_relays: Vec<String> = relays
            .iter()
            .filter(|r| {
                let url = match url::Url::parse(r) {
                    Ok(u) => u,
                    Err(_) => return false,
                };
                if url.scheme() != "wss" {
                    return true;
                }
                url.host_str().map(|h| pins.is_pinned(h)).unwrap_or(false)
            })
            .cloned()
            .collect();

        if verified_relays.is_empty() {
            return Err(keep_frost_net::FrostNetError::Transport(
                "No relays passed TLS certificate verification".into(),
            )
            .into());
        }

        Ok(verified_relays)
    }

    fn do_initialize(
        &self,
        relays: Vec<String>,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<(), KeepMobileError> {
        // Serialize install against a concurrent teardown (invalidate_live_node)
        // so the (node, node_tasks) pair is swapped atomically. Held for the
        // whole fn; neither path nests the other, so this cannot self-deadlock.
        // The guard spans the relay I/O below (TLS pin verification, connect), so
        // a concurrent teardown waits out the whole init; acceptable under the
        // single-user mobile FFI model where init runs off the UI thread.
        let _lifecycle = self
            .node_lifecycle_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Held across the whole init (including the block_on below, on this stack
        // frame rather than inside the future) so the trust-on-first-use auto-pin
        // persist cannot lose an update to a concurrent stage/remove/clear FFI
        // call. Lock order is node_lifecycle_lock -> cert_pin_lock; the FFI
        // cert-pin methods take only cert_pin_lock, so there is no cycle.
        let _cert_pins = self
            .cert_pin_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for relay in &relays {
            network::validate_relay_url(relay)?;
        }

        let share = self.load_share_package()?;

        self.runtime.block_on(async {
            let verified_relays = self.verify_and_pin_relays(&relays, proxy).await?;

            // Enforce the SPKI pin on the sockets that carry share and signing
            // traffic, not just on the pre-flight probe above.
            let pinning = self.live_pinning()?;
            let node = KfpNode::new_pinned(share, verified_relays, proxy, pinning).await?;

            let node = if let Some(path) = self
                .session_store_path
                .lock()
                .unwrap_or_else(|poisoned| {
                    tracing::error!("session_store_path lock poisoned: {poisoned:?}");
                    poisoned.into_inner()
                })
                .clone()
            {
                let store_path = std::path::PathBuf::from(path).join("descriptor-sessions.redb");
                match keep_frost_net::FileDescriptorSessionStore::new(&store_path) {
                    Ok(store) => node.with_descriptor_session_store(
                        Arc::new(store) as Arc<dyn keep_frost_net::DescriptorSessionStore>
                    ),
                    Err(e) => {
                        tracing::warn!(
                            "descriptor session store unavailable ({e}); \
                             continuing with in-memory sessions"
                        );
                        node
                    }
                }
            } else {
                node
            };

            let (request_tx, request_rx) = mpsc::channel(32);
            let hooks = Arc::new(MobileSigningHooks {
                request_tx,
                pre_approved_hashes: self.pre_approved_hashes.clone(),
                storage: self.storage.clone(),
            });
            node.set_hooks(hooks);

            let event_rx = node.subscribe();
            let node = Arc::new(node);
            let desc_ctx = DescriptorContext {
                callbacks: self.descriptor_callbacks.clone(),
                storage: self.storage.clone(),
                node: node.clone(),
                networks: self.descriptor_networks.clone(),
                pending: self.pending_contributions.clone(),
            };
            let state_ctx = StateContext {
                node: node.clone(),
                pending: self.pending_requests.clone(),
                callback: self.state_callback.clone(),
                rev: self.state_rev.clone(),
            };
            // Retire any prior node before starting the new one so its pending
            // requests are cleared up front. Clearing before the tasks below
            // spawn is what keeps the new session's requests: they can only be
            // enqueued once its listener/run tasks are live.
            self.retire_prior_node_tasks().await;

            let listener_handle = tokio::spawn(async move {
                Self::event_listener(event_rx, request_rx, desc_ctx, state_ctx).await;
            });

            let run_node = node.clone();
            let run_handle = tokio::spawn(async move {
                if let Err(e) = run_node.run().await {
                    tracing::error!("Node run failed: {e}");
                }
            });

            self.node_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend([listener_handle, run_handle]);

            *self.node.write().await = Some(node);
            Ok(())
        })
    }

    fn do_import_nsec(
        &self,
        hex_key: &str,
        name: String,
        plaintext_mnemonic: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<ShareInfo, KeepMobileError> {
        Self::validate_share_name(&name)?;

        let share_count = self.storage.list_all_shares().len();
        if share_count >= MAX_STORED_SHARES {
            return Err(KeepMobileError::StorageError {
                msg: "Maximum number of shares reached".into(),
            });
        }

        let key_bytes =
            Zeroizing::new(
                hex::decode(hex_key).map_err(|_| KeepMobileError::InvalidShare {
                    msg: "Invalid hex encoding".into(),
                })?,
            );

        if key_bytes.len() != 32 {
            return Err(KeepMobileError::InvalidShare {
                msg: "Key must be exactly 32 bytes".into(),
            });
        }

        let (key_package, pubkey_package, vk_bytes) = Self::build_nsec_packages(&key_bytes)?;
        let (metadata_info, stored) = Self::build_nsec_share_data(
            key_package,
            pubkey_package,
            vk_bytes,
            name,
            plaintext_mnemonic,
            false,
        )?;

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let group_pubkey_hex = hex::encode(&metadata_info.group_pubkey);
        self.storage.store_share_by_key(
            group_pubkey_hex.clone(),
            serialized,
            metadata_info.clone(),
        )?;
        self.storage
            .set_active_share_key(Some(group_pubkey_hex.clone()))?;

        self.invalidate_live_node();

        Ok(ShareInfo {
            name: metadata_info.name,
            share_index: metadata_info.identifier,
            threshold: metadata_info.threshold,
            total_shares: metadata_info.total_shares,
            group_pubkey: group_pubkey_hex,
        })
    }

    fn build_nsec_packages(
        key_bytes: &[u8],
    ) -> Result<
        (
            frost_secp256k1_tr::keys::KeyPackage,
            frost_secp256k1_tr::keys::PublicKeyPackage,
            Vec<u8>,
        ),
        KeepMobileError,
    > {
        // SigningKey doesn't implement Zeroize; deserialize, extract what we need,
        // and drop it promptly to minimize the window secret material is on the stack.
        let (vk, vk_bytes, signing_key_bytes) = {
            let signing_key =
                frost_secp256k1_tr::SigningKey::deserialize(key_bytes).map_err(|e| {
                    KeepMobileError::FrostError {
                        msg: format!("Invalid signing key: {e}"),
                    }
                })?;
            let vk = frost_secp256k1_tr::VerifyingKey::from(&signing_key);
            let vk_bytes = vk.serialize().map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to serialize verifying key: {e}"),
            })?;
            let skb = Zeroizing::new(signing_key.serialize());
            (vk, vk_bytes, skb)
        };

        let identifier = frost_secp256k1_tr::Identifier::try_from(1u16).map_err(|e| {
            KeepMobileError::FrostError {
                msg: format!("Failed to create identifier: {e}"),
            }
        })?;

        let signing_share = frost_secp256k1_tr::keys::SigningShare::deserialize(&signing_key_bytes)
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to create signing share: {e}"),
            })?;

        let verifying_share = frost_secp256k1_tr::keys::VerifyingShare::deserialize(&vk_bytes)
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to create verifying share: {e}"),
            })?;

        let key_package = frost_secp256k1_tr::keys::KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            vk,
            1,
        );

        let mut verifying_shares = std::collections::BTreeMap::new();
        verifying_shares.insert(identifier, verifying_share);
        // Some(1): 1-of-1 nsec import, matching the KeyPackage min_signers above.
        let pubkey_package =
            frost_secp256k1_tr::keys::PublicKeyPackage::new(verifying_shares, vk, Some(1));

        Ok((key_package, pubkey_package, vk_bytes))
    }

    fn build_nsec_share_data(
        key_package: frost_secp256k1_tr::keys::KeyPackage,
        pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
        vk_bytes: Vec<u8>,
        name: String,
        plaintext_mnemonic: Option<Zeroizing<Vec<u8>>>,
        did_backup: bool,
    ) -> Result<(ShareMetadataInfo, StoredShareData), KeepMobileError> {
        let group_pubkey: [u8; 32] = match vk_bytes.len() {
            33 => vk_bytes[1..33]
                .try_into()
                .map_err(|_| KeepMobileError::FrostError {
                    msg: "Failed to extract group pubkey from verifying key".into(),
                })?,
            len => {
                return Err(KeepMobileError::FrostError {
                    msg: format!("Invalid group pubkey length: {len}"),
                })
            }
        };

        let mut metadata = ShareMetadata::new(1, 1, 1, group_pubkey, name);
        if did_backup {
            metadata.mark_backed_up();
        }

        let metadata_info: ShareMetadataInfo = (&metadata).into();

        let stored = StoredShareData {
            metadata_json: serde_json::to_string(&metadata)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?,
            key_package_bytes: Zeroizing::new(key_package.serialize().map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                }
            })?),
            pubkey_package_bytes: pubkey_package.serialize().map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                }
            })?,
            plaintext_mnemonic,
            ciphersuite: keep_core::frost::Ciphersuite::Secp256k1Tr,
        };

        Ok((metadata_info, stored))
    }

    fn policy_read_lock(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, PolicyEvaluator>, KeepMobileError> {
        self.policy
            .read()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Policy lock poisoned".into(),
            })
    }

    fn policy_write_lock(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, PolicyEvaluator>, KeepMobileError> {
        self.policy
            .write()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Policy lock poisoned".into(),
            })
    }

    /// Loads the stored wardens and policy into `evaluator`, deciding which of
    /// the three states the records put it in.
    ///
    /// An absent record and an unreadable one are different statements.
    /// `load_share_by_key` answers `StorageNotFound` for absent, and a fault
    /// means the backend tried and could not, which on Android means the record
    /// is there and did not decrypt. So:
    ///
    /// - no policy record: no rules, nothing to enforce or to be unsure about.
    /// - policy unreadable: the rules are unknown, so every rule refuses.
    /// - policy present, wardens unreadable: the bundle cannot be attributed to
    ///   a signer, and an unattributable policy is not an absent one.
    /// - policy present and wardens known: verified, or faulted.
    ///
    /// Wardens absent and wardens unreadable both land on a refusal for a
    /// stored bundle on a fresh evaluator, because `verify_trusted_warden`
    /// refuses an empty set. A bundle can only have been stored while some
    /// warden was trusted, so an empty set with a bundle present means the
    /// record was lost, which is exactly the case that must not read as "no
    /// policy".
    fn load_policy_into(storage: &Arc<dyn SecureStorage>, evaluator: &mut PolicyEvaluator) {
        match persistence::load_trusted_wardens(storage) {
            Ok(wardens) => evaluator.set_trusted_wardens(wardens),
            Err(KeepMobileError::StorageNotFound) => {
                evaluator.set_trusted_wardens(std::collections::HashSet::new())
            }
            // Keep whatever set is already in memory rather than replacing it
            // with an empty one. On a fresh evaluator that set is empty anyway,
            // so a stored bundle still refuses for want of a signer; on a live
            // one it means a warden just added does not disappear because the
            // record could not be read back.
            Err(e) => tracing::error!(
                "Trusted wardens unreadable, keeping the set already in memory; a \
                 stored policy needing a warden outside it will refuse: {e}"
            ),
        }

        let bundle = match persistence::load_policy(storage) {
            Ok(bundle) => bundle,
            Err(KeepMobileError::StorageNotFound) => {
                evaluator.clear_policy();
                return;
            }
            // A record that will not parse will not parse next time either, so
            // it is not the retryable arm. Calling it unreadable would put two
            // Keystore decrypts on every decision for the life of the process
            // and tell the caller to wait out a fault that never clears.
            Err(e @ KeepMobileError::InvalidPolicy { .. }) => {
                tracing::error!("Stored policy could not be parsed, every rule will refuse: {e}");
                evaluator.set_policy_faulted(PolicyFault::Unverified, None);
                return;
            }
            Err(e) => {
                tracing::error!("Policy unreadable, every rule will refuse: {e}");
                evaluator.set_policy_faulted(PolicyFault::Unreadable, None);
                return;
            }
        };

        // Attribution before the clock, and in that order deliberately. The
        // signature, hash and signer are what make the bundle evidence; only
        // once they hold is its own `created_at` worth anything, which is what
        // lets a replacement be measured against an expired bundle rather than
        // the expired one having to be thrown away first.
        let attributed = bundle
            .verify_signature()
            .and_then(|()| bundle.verify_hash())
            .and_then(|()| bundle.verify_trusted_warden(evaluator.trusted_wardens()));
        if let Err(e) = attributed {
            tracing::error!("Stored policy did not verify, every rule will refuse: {e}");
            evaluator.set_policy_faulted(PolicyFault::Unverified, None);
            return;
        }

        match bundle.timestamp_fault() {
            None => evaluator.set_policy(bundle),
            Some(fault) => {
                tracing::error!(
                    "Stored policy is authentic but outside its validity window ({fault}), \
                     every rule will refuse"
                );
                evaluator.set_policy_faulted(fault, Some(bundle));
            }
        }
    }

    /// Reads the stored policy again if reading it again could change the
    /// answer.
    ///
    /// Only the transient faults are retried. A record that will not parse, or
    /// that is signed by nobody we trust, answers the same way every time, so
    /// retrying it would be two storage reads per decision for nothing; that
    /// one changes when the trusted wardens do, and both warden mutations
    /// re-run the load themselves.
    fn reload_policy_if_transient(&self) -> Result<(), KeepMobileError> {
        // Bound to a local first. Folding this into the `if` condition, or into
        // a `match`, keeps the read guard alive across `policy_write_lock` and
        // self-deadlocks on a lock that is not reentrant.
        let fault = self.policy_read_lock()?.fault();
        if !fault.is_some_and(PolicyFault::is_transient) {
            return Ok(());
        }
        let mut policy = self.policy_write_lock()?;
        Self::load_policy_into(&self.storage, &mut policy);
        Ok(())
    }

    /// Reads the stored counters again if they are still unknown.
    ///
    /// The fault that made them unknown can be transient: the Android Keystore
    /// backend documents a decrypt failure that leaves the record intact. Held
    /// for the life of the process, the refusal would outlast its cause and the
    /// only way out would be discarding the real history. Retried before each
    /// decision, a recovered Keystore restores the actual counters.
    ///
    /// A retry that fails changes nothing, so the counters are never read as
    /// empty by reaching here.
    fn reload_velocity_if_unknown(&self) -> Result<(), KeepMobileError> {
        let mut velocity = self.velocity_lock()?;
        if velocity.is_some() {
            return Ok(());
        }
        match persistence::load_velocity(&self.storage) {
            Ok(tracker) => *velocity = Some(tracker),
            Err(e) => tracing::warn!("Velocity counters still unreadable: {e}"),
        }
        Ok(())
    }

    fn velocity_lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<VelocityTracker>>, KeepMobileError> {
        self.velocity
            .lock()
            .map_err(|_| KeepMobileError::StorageError {
                msg: "Velocity lock poisoned".into(),
            })
    }
}

impl KeepMobile {
    fn validate_share_name(name: &str) -> Result<(), KeepMobileError> {
        if name.chars().count() > MAX_SHARE_NAME_LENGTH {
            return Err(KeepMobileError::InvalidShare {
                msg: format!(
                    "Share name exceeds maximum length of {MAX_SHARE_NAME_LENGTH} characters"
                ),
            });
        }
        Ok(())
    }

    fn build_generation_result(
        shares: &[SharePackage],
        passphrase: &Zeroizing<String>,
    ) -> Result<FrostGenerationResult, KeepMobileError> {
        let mut share_infos = Vec::with_capacity(shares.len());

        for share in shares {
            let export = ShareExport::from_share(share, passphrase)?;
            let export_data = export.to_text()?;

            share_infos.push(GeneratedShareInfo {
                share_index: share.metadata.identifier,
                threshold: share.metadata.threshold,
                total_shares: share.metadata.total_shares,
                group_pubkey: hex::encode(share.metadata.group_pubkey),
                export_data,
            });
        }

        let group_pubkey = shares
            .first()
            .map(|s| hex::encode(s.metadata.group_pubkey))
            .unwrap_or_default();

        Ok(FrostGenerationResult {
            group_pubkey,
            shares: share_infos,
        })
    }

    fn store_share_package(&self, share: &SharePackage) -> Result<ShareInfo, KeepMobileError> {
        let metadata: ShareMetadataInfo = (&share.metadata).into();

        let stored = StoredShareData {
            metadata_json: serde_json::to_string(&share.metadata)
                .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?,
            key_package_bytes: Zeroizing::new(
                share
                    .key_package()
                    .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
                    .serialize()
                    .map_err(|e| KeepMobileError::FrostError {
                        msg: format!("Serialization failed: {e}"),
                    })?,
            ),
            pubkey_package_bytes: share
                .pubkey_package()
                .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?
                .serialize()
                .map_err(|e| KeepMobileError::FrostError {
                    msg: format!("Serialization failed: {e}"),
                })?,
            plaintext_mnemonic: None,
            ciphersuite: keep_core::frost::Ciphersuite::Secp256k1Tr,
        };

        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| KeepMobileError::StorageError { msg: e.to_string() })?;

        let group_pubkey_hex = hex::encode(&metadata.group_pubkey);
        self.storage
            .store_share_by_key(group_pubkey_hex.clone(), serialized, metadata.clone())?;
        self.storage
            .set_active_share_key(Some(group_pubkey_hex.clone()))?;

        self.invalidate_live_node();

        Ok(ShareInfo {
            name: metadata.name,
            share_index: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            group_pubkey: group_pubkey_hex,
        })
    }

    async fn event_listener(
        mut event_rx: broadcast::Receiver<KfpNodeEvent>,
        mut request_rx: mpsc::Receiver<(SessionInfo, mpsc::Sender<bool>)>,
        desc: DescriptorContext,
        state: StateContext,
    ) {
        // FIXME: connection_status is hardcoded; KfpNodeEvent doesn't
        // emit connect/disconnect events yet, so we can't track real state.
        let connection_status = ConnectionStatus::Connected;
        state.push(&connection_status).await;
        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(KfpNodeEvent::SignatureComplete { session_id, .. })
                        | Ok(KfpNodeEvent::SigningFailed { session_id, .. }) => {
                            let id = hex::encode(session_id);
                            let mut guard = state.pending.lock().await;
                            guard.retain(|r| r.info.id != id);
                            drop(guard);
                            state.push(&connection_status).await;
                        }
                        Ok(KfpNodeEvent::DescriptorContributionNeeded {
                            session_id,
                            policy,
                            network,
                            initiator_pubkey,
                        }) => {
                            let nets_ok = match desc.networks.lock() {
                                Ok(mut nets) => {
                                    nets.insert(session_id, network.clone());
                                    true
                                }
                                Err(e) => {
                                    tracing::error!("Descriptor networks lock poisoned: {e}");
                                    false
                                }
                            };
                            if nets_ok {
                                match desc.pending.lock() {
                                    Ok(mut p) => {
                                        p.retain(|_, c| c.created_at.elapsed() < DESCRIPTOR_SESSION_TIMEOUT);
                                        p.insert(session_id, PendingContribution {
                                            network: network.clone(),
                                            initiator_pubkey,
                                            created_at: std::time::Instant::now(),
                                        });
                                    }
                                    Err(e) => {
                                        tracing::error!("Pending contributions lock poisoned: {e}");
                                    }
                                }
                            }
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                let tiers = policy.recovery_tiers.iter().map(|t| {
                                    RecoveryTierConfig {
                                        threshold: t.threshold,
                                        timelock_months: t.timelock_months,
                                    }
                                }).collect();
                                if let Err(e) = cb.on_contribution_needed(DescriptorProposal {
                                    session_id: hex::encode(session_id),
                                    network,
                                    tiers,
                                }) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorProposed { session_id }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_proposed(hex::encode(session_id)) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorContributed {
                            session_id,
                            share_index,
                        }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_contributed(hex::encode(session_id), share_index) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorReady { session_id }) => {
                            if let Err(e) = desc.node.build_and_finalize_descriptor(session_id).await {
                                tracing::error!("Failed to finalize descriptor: {e}");
                                clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                                if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                    if let Err(e2) = cb.on_failed(hex::encode(session_id), e.to_string()) {
                                        tracing::error!("Descriptor callback error: {e2}");
                                    }
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorComplete {
                            session_id,
                            external_descriptor,
                            internal_descriptor,
                            network,
                            policy_hash,
                            version,
                            policy,
                        }) => {
                            let policy_json = match serde_json::to_string(&policy) {
                                Ok(s) => Some(s),
                                Err(e) => {
                                    tracing::error!("Failed to serialize descriptor policy: {e}");
                                    clear_descriptor_state(
                                        &desc.networks,
                                        &desc.pending,
                                        &session_id,
                                    );
                                    if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                        if let Err(e2) = cb.on_failed(
                                            hex::encode(session_id),
                                            format!("Failed to serialize descriptor policy: {e}"),
                                        ) {
                                            tracing::error!("Descriptor callback error: {e2}");
                                        }
                                    }
                                    continue;
                                }
                            };
                            if let Ok(mut p) = desc.pending.lock() {
                                p.remove(&session_id);
                            }
                            let network = match Some(network).filter(|n| !n.is_empty()) {
                                Some(n) => n,
                                _ => {
                                    tracing::error!("Missing network for descriptor session");
                                    if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                        if let Err(e) = cb.on_failed(
                                            hex::encode(session_id),
                                            "Missing network for descriptor session".into(),
                                        ) {
                                            tracing::error!("Descriptor callback error: {e}");
                                        }
                                    }
                                    continue;
                                }
                            };
                            Self::handle_descriptor_complete(
                                &desc.storage,
                                &desc.callbacks,
                                &desc.node,
                                network,
                                session_id,
                                external_descriptor,
                                internal_descriptor,
                                policy_hash,
                                version,
                                policy_json,
                            )
                            .await;
                        }
                        Ok(KfpNodeEvent::DescriptorNacked {
                            session_id,
                            share_index,
                            reason,
                        }) => {
                            clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                            let error =
                                format!("Peer {share_index} rejected descriptor: {reason}");
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_failed(hex::encode(session_id), error) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::DescriptorFailed { session_id, error }) => {
                            clear_descriptor_state(&desc.networks, &desc.pending, &session_id);
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                if let Err(e) = cb.on_failed(hex::encode(session_id), error) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::XpubAnnounced {
                            share_index,
                            recovery_xpubs,
                        }) => {
                            if let Some(cb) = desc.callbacks.read().await.as_ref() {
                                let xpubs = recovery_xpubs
                                    .into_iter()
                                    .map(|x| AnnouncedXpubInfo {
                                        xpub: x.xpub,
                                        fingerprint: x.fingerprint,
                                        label: x.label,
                                    })
                                    .collect();
                                if let Err(e) = cb.on_xpub_announced(share_index, xpubs) {
                                    tracing::error!("Descriptor callback error: {e}");
                                }
                            }
                        }
                        Ok(KfpNodeEvent::PeerDiscovered { .. })
                        | Ok(KfpNodeEvent::PeerOffline { .. }) => {
                            state.push(&connection_status).await;
                        }
                        Ok(KfpNodeEvent::VerifyingSharesLearned {
                            share_index,
                            verifying_shares,
                        }) => {
                            if let Err(e) = store_learned_verifying_shares(
                                desc.storage.as_ref(),
                                desc.node.group_pubkey(),
                                share_index,
                                &verifying_shares,
                            ) {
                                tracing::error!("Failed to store learned verifying shares: {e}");
                            }
                        }
                        Ok(KfpNodeEvent::PeerVersionMismatch {
                            share_index,
                            version,
                        }) => {
                            tracing::warn!(
                                share_index,
                                version,
                                "peer runs another protocol version; every member must run v{}",
                                keep_frost_net::KFP_VERSION
                            );
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            state.push(&connection_status).await;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = request_rx.recv() => {
                    let Some((session, response_tx)) = result else {
                        break;
                    };
                    let mut guard = state.pending.lock().await;
                    if guard.len() >= MAX_PENDING_REQUESTS {
                        let _ = response_tx.send(false).await;
                        continue;
                    }
                    guard.push(PendingRequest {
                        info: sign_request_from_session(&session),
                        response_tx,
                    });
                    drop(guard);
                    state.push(&connection_status).await;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_descriptor_complete(
        storage: &Arc<dyn SecureStorage>,
        cbs: &Arc<RwLock<Option<Arc<dyn DescriptorCallbacks>>>>,
        node: &Arc<KfpNode>,
        network: String,
        session_id: [u8; 32],
        external_descriptor: String,
        internal_descriptor: String,
        policy_hash: [u8; 32],
        version: u32,
        policy_json: Option<String>,
    ) {
        let group_pubkey = hex::encode(node.group_pubkey());
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // For v2+ completions, look up the currently-persisted descriptor for
        // this group and record its canonical hash as the predecessor so
        // lineage is preserved at the moment of persistence. For v1 (initial
        // descriptor) there is no lineage by definition. Mirror the CLI's
        // immediate-predecessor check: refuse to persist a migration whose
        // predecessor is missing, malformed, or not at `version - 1`.
        let previous_descriptor_hash_hex = if version
            > keep_core::wallet::INITIAL_DESCRIPTOR_VERSION
        {
            let prev = match persistence::load_descriptor(storage, &group_pubkey) {
                Ok(prev) => prev,
                Err(e) => {
                    tracing::error!(
                        version,
                        error = %e,
                        "refusing to persist migrated descriptor: no predecessor descriptor found"
                    );
                    if let Some(cb) = cbs.read().await.as_ref() {
                        let _ = cb.on_failed(
                            hex::encode(session_id),
                            format!("Missing predecessor descriptor for v{version}: {e}"),
                        );
                    }
                    return;
                }
            };
            if prev.version != version - 1 {
                tracing::error!(
                    version,
                    predecessor_version = prev.version,
                    "refusing to persist migrated descriptor: predecessor is not the immediate predecessor"
                );
                if let Some(cb) = cbs.read().await.as_ref() {
                    let _ = cb.on_failed(
                        hex::encode(session_id),
                        format!(
                            "Predecessor descriptor v{} is not the immediate predecessor of v{}",
                            prev.version, version
                        ),
                    );
                }
                return;
            }
            let prev_policy_hash = match prev.policy_hash_hex.as_deref() {
                Some(h) => match hex::decode(h)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    Some(arr) => arr,
                    None => {
                        tracing::error!(
                            "refusing to persist migrated descriptor: predecessor policy_hash_hex is malformed"
                        );
                        if let Some(cb) = cbs.read().await.as_ref() {
                            let _ = cb.on_failed(
                                hex::encode(session_id),
                                "Predecessor descriptor has malformed policy_hash_hex".into(),
                            );
                        }
                        return;
                    }
                },
                // Legacy descriptors written before `policy_hash` was added
                // serialize the field as `[0u8; 32]` via `#[serde(default)]`,
                // and the mobile surface maps that zero value back to `None`.
                // The predecessor's canonical hash was originally computed
                // with zeros, so matching that is the correct recomputation,
                // not a fail-closed condition.
                None => [0u8; 32],
            };
            match keep_core::wallet::canonical_descriptor_hash(
                &prev.external_descriptor,
                &prev.internal_descriptor,
                &prev_policy_hash,
                prev.version,
            ) {
                Ok(hash) => Some(hex::encode(hash)),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "refusing to persist migrated descriptor: predecessor hash computation failed"
                    );
                    if let Some(cb) = cbs.read().await.as_ref() {
                        let _ = cb.on_failed(
                            hex::encode(session_id),
                            format!("Predecessor hash computation failed: {e}"),
                        );
                    }
                    return;
                }
            }
        } else {
            None
        };

        let info = WalletDescriptorInfo {
            group_pubkey,
            external_descriptor: external_descriptor.clone(),
            internal_descriptor: internal_descriptor.clone(),
            network,
            created_at,
            device_registrations: Vec::new(),
            policy_hash_hex: if policy_hash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(policy_hash))
            },
            version,
            previous_descriptor_hash_hex,
            policy_json,
        };

        if let Err(e) = persistence::persist_descriptor(storage, &info) {
            tracing::error!("Failed to persist descriptor: {e}");
            if let Some(cb) = cbs.read().await.as_ref() {
                if let Err(e2) = cb.on_failed(
                    hex::encode(session_id),
                    format!("Failed to persist descriptor: {e}"),
                ) {
                    tracing::error!("Descriptor callback error: {e2}");
                }
            }
            return;
        }

        if let Some(cb) = cbs.read().await.as_ref() {
            if let Err(e) = cb.on_complete(
                hex::encode(session_id),
                external_descriptor,
                internal_descriptor,
            ) {
                tracing::error!("Descriptor callback error: {e}");
            }
        }
    }

    fn load_share_package(&self) -> Result<SharePackage, KeepMobileError> {
        let key = match self.storage.get_active_share_key() {
            Some(k) => k,
            None => self.resolve_active_share()?,
        };
        let data = self.storage.load_share_by_key(key.clone())?;
        let stored: StoredShareData = serde_json::from_slice(&data)
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        let mut metadata: keep_core::frost::ShareMetadata =
            serde_json::from_str(&stored.metadata_json)
                .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;

        if let Some(display_name) = self
            .storage
            .get_share_metadata()
            .filter(|m| {
                m.group_pubkey == metadata.group_pubkey && m.identifier == metadata.identifier
            })
            .map(|m| m.name)
        {
            if display_name != metadata.name {
                metadata.name = display_name;
            }
        }

        if stored.ciphersuite != keep_core::frost::Ciphersuite::Secp256k1Tr {
            return Err(KeepMobileError::InvalidShare {
                msg: "Only secp256k1 (Bitcoin/Nostr) shares are supported on mobile".into(),
            });
        }

        let key_package = frost_secp256k1_tr::keys::KeyPackage::deserialize(
            &stored.key_package_bytes,
        )
        .map_err(|e| KeepMobileError::InvalidShare {
            msg: format!("Invalid key package: {e}"),
        })?;

        let pubkey_package =
            frost_secp256k1_tr::keys::PublicKeyPackage::deserialize(&stored.pubkey_package_bytes)
                .map_err(|e| KeepMobileError::InvalidShare {
                msg: format!("Invalid pubkey package: {e}"),
            })?;

        let share = SharePackage::new(metadata, &key_package, &pubkey_package)
            .map_err(|e| KeepMobileError::FrostError { msg: e.to_string() })?;

        // Defense-in-depth against a compromised or buggy foreign SecureStorage:
        // the share's group key read from its public-key package (not the
        // separate, forgeable metadata field) MUST match the key it was requested
        // under. This detects a store that returns a share for a *different*
        // group, or a corrupted one, rather than loading it as the requested
        // identity. A store that pairs the expected verifying key with junk key
        // material still passes here but fails at signing; confidentiality and
        // same-identity tamper-resistance rest on the platform secure storage.
        let derived = share
            .verified_group_pubkey()
            .map_err(|e| KeepMobileError::InvalidShare { msg: e.to_string() })?;
        if !key.eq_ignore_ascii_case(&hex::encode(derived)) {
            return Err(KeepMobileError::InvalidShare {
                msg: "stored share does not match its group key; the secure storage returned a \
                      different or corrupted share"
                    .into(),
            });
        }
        Ok(share)
    }

    fn load_stored_share_info(&self, key: String) -> Option<StoredShareInfo> {
        // A share record that is referenced (by the metadata list or the
        // active-share pointer) but cannot be read back or parsed is corruption
        // or a failing storage layer, not an absent share. Log the distinction
        // instead of silently collapsing it to "no share", so a corrupt active
        // share is observable rather than looking like an un-provisioned device
        // (#792). The return stays `Option`; letting callers tell corruption from
        // absence needs an FFI-breaking `Result` change, tracked separately.
        let data = match self.storage.load_share_by_key(key.clone()) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("failed to load stored share for key {key}: {e}");
                return None;
            }
        };
        let stored: StoredShareData = match serde_json::from_slice(&data) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::warn!("corrupt stored share data for key {key}: {e}");
                return None;
            }
        };
        let metadata: keep_core::frost::ShareMetadata =
            match serde_json::from_str(&stored.metadata_json) {
                Ok(metadata) => metadata,
                Err(e) => {
                    tracing::warn!("corrupt share metadata for key {key}: {e}");
                    return None;
                }
            };

        Some(StoredShareInfo {
            group_pubkey: key,
            name: metadata.name.clone(),
            share_index: metadata.identifier,
            threshold: metadata.threshold,
            total_shares: metadata.total_shares,
            created_at: metadata.created_at,
            last_used: metadata.last_used,
            sign_count: metadata.sign_count,
            did_backup: metadata.did_backup,
        })
    }

    /// Resolve an active share for this call, without writing a pointer.
    ///
    /// `list_all_shares` has no error channel, so a platform storage fault is
    /// indistinguishable from a genuinely short set: a fault that leaves one
    /// readable share looks exactly like owning one share. Persisting the
    /// inferred pointer turned that transient fault into a permanent repoint of
    /// the active account, which outlived the fault and was never surfaced.
    /// Resolving per call keeps the convenience and lets a later call see the
    /// full set once storage recovers, at which point the `_` arm errors rather
    /// than standing on a stale choice.
    ///
    /// Two things this does not achieve, both needing work outside this layer.
    /// `load_share_package` consults `get_active_share_key` first, and the
    /// Android implementation of that getter is itself a resolver that infers a
    /// pointer from its registry and persists it, for any share count, so the
    /// write still happens one layer down and the `_` arm below is not reached
    /// through it. And the `0` arm calls `migrate_legacy_share`, which writes a
    /// share and a pointer off the same untrusted list; telling that empty list
    /// from a fault needs the error channel `list_all_shares` lacks.
    fn resolve_active_share(&self) -> Result<String, KeepMobileError> {
        let shares = self.storage.list_all_shares();
        match shares.len() {
            1 => Ok(hex::encode(&shares[0].group_pubkey)),
            0 => self.migrate_legacy_share(),
            _ => Err(KeepMobileError::StorageError {
                msg: "Multiple shares found, please select one".into(),
            }),
        }
    }

    fn migrate_legacy_share(&self) -> Result<String, KeepMobileError> {
        if !self.storage.has_share() {
            return Err(KeepMobileError::StorageError {
                msg: "No active share set".into(),
            });
        }

        let legacy_data = self.storage.load_share()?;
        let legacy_metadata =
            self.storage
                .get_share_metadata()
                .ok_or(KeepMobileError::StorageError {
                    msg: "Legacy share missing metadata".into(),
                })?;

        let key = hex::encode(&legacy_metadata.group_pubkey);

        self.storage
            .store_share_by_key(key.clone(), legacy_data, legacy_metadata)?;
        self.storage.set_active_share_key(Some(key.clone()))?;

        Ok(key)
    }
}

#[cfg(test)]
mod import_teardown_tests {
    use super::*;
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MemStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
        active: StdMutex<Option<String>>,
    }

    impl SecureStorage for MemStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            self.active.lock().unwrap().clone()
        }
        fn set_active_share_key(&self, key: Option<String>) -> Result<(), KeepMobileError> {
            *self.active.lock().unwrap() = key;
            Ok(())
        }
    }

    // Seed one pending request so we can observe invalidate_live_node running:
    // the node starts None in this harness (a real KfpNode needs a live
    // network), so the pending request it clears is the observable proof the
    // teardown block ran on the import path.
    fn seed_pending_request(mobile: &KeepMobile) {
        let (tx, _rx) = mpsc::channel::<bool>(1);
        mobile.runtime.block_on(async {
            mobile.pending_requests.lock().await.push(PendingRequest {
                info: SignRequest {
                    id: "seed".into(),
                    session_id: vec![0u8; 32],
                    message_type: String::new(),
                    type_verified: false,
                    message_preview: String::new(),
                    from_peer: 0,
                    timestamp: 0,
                    metadata: None,
                },
                response_tx: tx,
            });
        });
    }

    fn assert_pending_cleared(mobile: &KeepMobile) {
        mobile.runtime.block_on(async {
            assert!(
                mobile.pending_requests.lock().await.is_empty(),
                "import must clear pending requests via node teardown"
            );
        });
    }

    // A successful import must run invalidate_live_node, the same teardown
    // set_active_share does, so the imported group can announce without a
    // restart. Before the fix it never ran on the import path.
    #[test]
    fn import_nsec_runs_node_teardown() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        seed_pending_request(&mobile);

        use nostr_sdk::prelude::{SecretKey, ToBech32};
        let nsec = SecretKey::from_slice(&[1u8; 32])
            .unwrap()
            .to_bech32()
            .unwrap();
        let info = mobile
            .import_nsec(nsec.into_bytes(), "imported".into())
            .unwrap();

        assert_pending_cleared(&mobile);
        assert_eq!(
            storage.get_active_share_key().as_deref(),
            Some(info.group_pubkey.as_str())
        );
    }

    #[test]
    fn learned_verifying_shares_complete_a_stored_share() {
        use keep_core::frost::{ThresholdConfig, TrustedDealer};

        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let (shares, _) = TrustedDealer::new(ThresholdConfig::new(3, 5).unwrap())
            .generate("learned")
            .unwrap();
        let full = shares[0].pubkey_package().unwrap();
        let set = keep_core::frost::verifying_share_map(&full, 5).unwrap();
        let mut export = ShareExport::from_share(&shares[0], "pass").unwrap();
        export.encrypted_pubkey_package = None;
        export.pubkey_nonce = None;
        export.encrypted_verifying_shares = None;
        export.verifying_shares_nonce = None;
        mobile
            .import_share(export.to_json().unwrap(), "pass".into(), "learned".into())
            .unwrap();
        let group = *shares[0].group_pubkey();
        assert_eq!(
            mobile
                .load_share_package()
                .unwrap()
                .pubkey_package()
                .unwrap()
                .verifying_shares()
                .len(),
            1
        );

        let mut forged = set.clone();
        forged.insert(3, set[&4]);
        assert!(store_learned_verifying_shares(storage.as_ref(), &group, 1, &forged).is_err());
        store_learned_verifying_shares(storage.as_ref(), &group, 1, &set).unwrap();
        let completed = mobile.load_share_package().unwrap();
        assert_eq!(
            completed.pubkey_package().unwrap().verifying_shares(),
            full.verifying_shares()
        );
        assert_eq!(completed.metadata.name, "learned");
    }

    // A platform storage fault that hides shares makes `list_all_shares` return
    // a short list, and a short list holding exactly one entry is
    // indistinguishable from owning one share. Resolving it is fine; writing it
    // is not, because the pointer outlives the fault and silently repoints the
    // active account.
    #[test]
    fn resolving_an_active_share_does_not_persist_the_pointer() {
        struct TruncatingStorage {
            inner: MemStorage,
            listed: StdMutex<Vec<ShareMetadataInfo>>,
        }

        impl SecureStorage for TruncatingStorage {
            fn store_share(&self, d: Vec<u8>, m: ShareMetadataInfo) -> Result<(), KeepMobileError> {
                self.inner.store_share(d, m)
            }
            fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
                self.inner.load_share()
            }
            fn has_share(&self) -> bool {
                self.inner.has_share()
            }
            fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
                self.inner.get_share_metadata()
            }
            fn delete_share(&self) -> Result<(), KeepMobileError> {
                self.inner.delete_share()
            }
            fn store_share_by_key(
                &self,
                k: String,
                d: Vec<u8>,
                m: ShareMetadataInfo,
            ) -> Result<(), KeepMobileError> {
                self.inner.store_share_by_key(k, d, m)
            }
            fn load_share_by_key(&self, k: String) -> Result<Vec<u8>, KeepMobileError> {
                self.inner.load_share_by_key(k)
            }
            // The fault, and its recovery: the records stay put while this
            // reports a subset of them.
            fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
                self.listed.lock().unwrap().clone()
            }
            fn delete_share_by_key(&self, k: String) -> Result<(), KeepMobileError> {
                self.inner.delete_share_by_key(k)
            }
            fn get_active_share_key(&self) -> Option<String> {
                self.inner.get_active_share_key()
            }
            fn set_active_share_key(&self, k: Option<String>) -> Result<(), KeepMobileError> {
                self.inner.set_active_share_key(k)
            }
        }

        let meta = |name: &str, b: u8| ShareMetadataInfo {
            name: name.into(),
            identifier: 1,
            threshold: 2,
            total_shares: 3,
            group_pubkey: vec![b; 32],
            did_backup: false,
        };
        let survivor = meta("survivor", 0xaa);
        let hidden = meta("hidden", 0xbb);

        let faulty = Arc::new(TruncatingStorage {
            inner: MemStorage::default(),
            listed: StdMutex::new(vec![survivor.clone()]),
        });
        let storage: Arc<dyn SecureStorage> = faulty.clone();
        // Both shares are on disk throughout; only the listing is short.
        for m in [&survivor, &hidden] {
            storage
                .store_share_by_key(hex::encode(&m.group_pubkey), b"share".to_vec(), m.clone())
                .unwrap();
        }
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        assert!(
            storage.get_active_share_key().is_none(),
            "precondition: no pointer is set, so resolve runs"
        );
        assert_eq!(
            mobile.resolve_active_share().unwrap(),
            hex::encode([0xaau8; 32]),
            "the single listed share still resolves for this call"
        );
        assert!(
            storage.get_active_share_key().is_none(),
            "a pointer inferred from an untrusted list must not be written"
        );

        *faulty.listed.lock().unwrap() = vec![survivor, hidden];
        assert!(
            mobile.resolve_active_share().is_err(),
            "once the fault clears, the ambiguity is reported rather than resolved \
             silently from the earlier short list"
        );
        assert!(
            storage.get_active_share_key().is_none(),
            "and no stale pointer is left behind to stand on"
        );
    }

    // Deleting a share must tear the live node down even when no pointer names
    // it. `load_share_package` resolves the share when the pointer is absent, so
    // a node can be running on a share the pointer never named; gating teardown
    // on the pointer left that node holding the deleted share's key material
    // with its queued requests still approvable.
    #[test]
    fn deleting_a_share_tears_down_a_node_the_pointer_never_named() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let group_hex = hex::encode([0xaau8; 32]);

        assert!(
            storage.get_active_share_key().is_none(),
            "precondition: the node was built from a resolved share, not a pointer"
        );
        seed_pending_request(&mobile);
        mobile.delete_share_by_key(group_hex).unwrap();
        mobile.runtime.block_on(async {
            assert!(
                mobile.pending_requests.lock().await.is_empty(),
                "deleting a share must run node teardown whether or not the \
                 pointer named it"
            );
        });
    }

    // A delete that reports failure must still tear the node down, because
    // `SecureStorage::delete_share_by_key` is not atomic: the Android
    // implementation clears the share data, then deletes the keystore aliases,
    // then rewrites the registry, and either of the last two fails after the
    // data is already gone. So an `Err` does not mean the share survived, and
    // skipping the teardown on it would leave the live node holding the only
    // remaining copy of a share the platform had already destroyed, still on
    // the relays, while the caller is told the delete failed.
    #[test]
    fn a_failed_share_delete_still_tears_down_the_live_node() {
        struct UndeletableStorage(MemStorage);

        impl SecureStorage for UndeletableStorage {
            fn store_share(&self, d: Vec<u8>, m: ShareMetadataInfo) -> Result<(), KeepMobileError> {
                self.0.store_share(d, m)
            }
            fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
                self.0.load_share()
            }
            fn has_share(&self) -> bool {
                self.0.has_share()
            }
            fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
                self.0.get_share_metadata()
            }
            fn delete_share(&self) -> Result<(), KeepMobileError> {
                self.0.delete_share()
            }
            fn store_share_by_key(
                &self,
                k: String,
                d: Vec<u8>,
                m: ShareMetadataInfo,
            ) -> Result<(), KeepMobileError> {
                self.0.store_share_by_key(k, d, m)
            }
            fn load_share_by_key(&self, k: String) -> Result<Vec<u8>, KeepMobileError> {
                self.0.load_share_by_key(k)
            }
            fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
                self.0.list_all_shares()
            }
            fn delete_share_by_key(&self, _: String) -> Result<(), KeepMobileError> {
                Err(KeepMobileError::StorageError {
                    msg: "cannot delete right now".into(),
                })
            }
            fn get_active_share_key(&self) -> Option<String> {
                self.0.get_active_share_key()
            }
            fn set_active_share_key(&self, k: Option<String>) -> Result<(), KeepMobileError> {
                self.0.set_active_share_key(k)
            }
        }

        let storage: Arc<dyn SecureStorage> = Arc::new(UndeletableStorage(MemStorage::default()));
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        seed_pending_request(&mobile);
        mobile
            .delete_share_by_key(hex::encode([0xaau8; 32]))
            .expect_err("the storage delete fails");
        mobile.runtime.block_on(async {
            assert!(
                mobile.pending_requests.lock().await.is_empty(),
                "a failed delete may already have destroyed the share, so the \
                 node must not be left holding it"
            );
        });
    }

    // A backup must still be produced when a descriptor record cannot be read.
    // Refusing denies the shares too, and the shares are the irreplaceable part
    // while a descriptor is public xpub data; the shipped consumer also has no
    // way to act on a refusal, since it shows a static error and can only pass
    // `wallet_descriptor_delete` a group the list returned, which excludes the
    // entry that is blocking. The incompleteness is reported instead.
    #[test]
    fn create_backup_proceeds_when_a_descriptor_record_cannot_be_read() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let orphan = "aa".repeat(32);

        // An index entry whose record never landed, which is what a failed
        // descriptor save or a platform wipe leaves behind.
        storage
            .store_share_by_key(
                DESCRIPTOR_INDEX_KEY.into(),
                serde_json::to_vec(&vec![orphan]).unwrap(),
                persistence::storage_metadata("descriptor_index"),
            )
            .unwrap();

        mobile
            .create_backup("a-sufficiently-long-passphrase".into())
            .expect("an unreadable descriptor must not deny the share backup");
    }

    // The list surface must not hand foreign code a raw registration token,
    // while the internal path that needs it must still see it: `create_backup`
    // reads `hmac` off the same `load_descriptors` value, and a backup stripped
    // of the tokens loses for good the opaque value the device returned.
    #[test]
    fn listing_descriptors_does_not_expose_the_registration_hmac() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let group = "bb".repeat(32);
        let token = "cd".repeat(32);

        let mut desc = WalletDescriptorInfo {
            group_pubkey: group.clone(),
            external_descriptor: "wpkh(xpub.../0/*)".into(),
            internal_descriptor: "wpkh(xpub.../1/*)".into(),
            network: "bitcoin".into(),
            created_at: 1_700_000_000,
            device_registrations: vec![],
            policy_hash_hex: None,
            version: 1,
            previous_descriptor_hash_hex: None,
            policy_json: None,
        };
        desc.device_registrations.push(DeviceRegistrationInfo {
            signer_pubkey: "ee".repeat(32),
            wallet_name: "signer".into(),
            hmac: Some(token.clone()),
            registered_at: 1_700_000_000,
            device_kind: None,
            fingerprint_hex: None,
            firmware_version: None,
        });
        persistence::persist_descriptor(&storage, &desc).unwrap();

        let listed = mobile.wallet_descriptor_list();
        assert_eq!(listed.len(), 1, "the descriptor is listed");
        assert_eq!(
            listed[0].device_registrations.len(),
            1,
            "the registration itself is still reported"
        );
        assert!(
            listed[0].device_registrations[0].hmac.is_none(),
            "the raw registration token must not cross the UniFFI boundary"
        );

        let load = persistence::load_descriptors(&storage).unwrap();
        assert_eq!(
            load.loaded[0].device_registrations[0].hmac.as_deref(),
            Some(token.as_str()),
            "the backup path must still see the token the list hides"
        );

        // Pin the token into the backup itself, not just into the shared
        // conversion: a `create_backup` rewritten to read the stripped list
        // would drop the tokens from every backup, and the assertion above
        // would not catch it.
        let pass = "a-sufficiently-long-passphrase";
        let bytes = mobile.create_backup(pass.into()).unwrap();
        let decrypted = decrypt_backup_data(&bytes, pass).unwrap();
        let backed_up = &decrypted.wallet_descriptors[0].device_registrations[0];
        assert_eq!(
            backed_up.hmac.as_deref().map(|h| hex::encode(h.as_slice())),
            Some(token.clone()),
            "the backup must carry the registration token"
        );
    }

    // A corrupt active-share record must degrade gracefully to `None` without
    // panicking: the active-share pointer is set, but its backing bytes are not
    // valid share data. `get_active_share` returning `None` here is the fail-safe
    // behavior (the caller sees no share); the value of #792 is that the
    // corruption is now logged rather than silently swallowed.
    #[test]
    fn get_active_share_returns_none_on_corrupt_record() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let key = "deadbeef".to_string();
        let meta = ShareMetadataInfo {
            name: "corrupt".into(),
            identifier: 1,
            threshold: 2,
            total_shares: 3,
            group_pubkey: vec![0u8; 32],
            did_backup: false,
        };
        // Seed unparseable bytes under a key the active-share pointer references.
        storage
            .store_share_by_key(key.clone(), b"not valid share json".to_vec(), meta)
            .unwrap();
        storage.set_active_share_key(Some(key)).unwrap();

        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        assert!(
            mobile.get_active_share().is_none(),
            "a corrupt active-share record must degrade to None, not panic"
        );
        assert!(
            mobile.get_active_share_metadata().is_none(),
            "corrupt active-share metadata must degrade to None, not panic"
        );
    }

    #[test]
    fn import_nsec_rejects_invalid_nsec_bytes() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        // Not a bech32 nsec at all.
        assert!(matches!(
            mobile.import_nsec(b"not-an-nsec".to_vec(), "x".into()),
            Err(KeepMobileError::InvalidShare { .. })
        ));
        // Non-UTF-8 bytes are rejected before any bech32 parsing.
        assert!(matches!(
            mobile.import_nsec(vec![0xff, 0xfe], "x".into()),
            Err(KeepMobileError::InvalidShare { .. })
        ));
    }

    #[test]
    fn validate_mnemonic_accepts_valid_bytes_and_rejects_garbage() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let mnemonic = mobile.generate_mnemonic(12).unwrap();
        assert!(mobile.validate_mnemonic(mnemonic).is_ok());

        // Well-formed UTF-8 but not a valid BIP-39 phrase.
        assert!(mobile
            .validate_mnemonic(b"not a valid mnemonic phrase at all".to_vec())
            .is_err());
        // Non-UTF-8 bytes.
        assert!(matches!(
            mobile.validate_mnemonic(vec![0xff, 0xfe]),
            Err(KeepMobileError::InvalidInput { .. })
        ));
    }

    #[test]
    fn create_account_from_mnemonic_bytes_round_trips() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let mnemonic = mobile.generate_mnemonic(12).unwrap();
        let info = mobile
            .create_account_from_mnemonic(mnemonic, String::new(), "acct".into())
            .unwrap();
        assert!(!info.group_pubkey.is_empty());
        assert_eq!(
            storage.get_active_share_key().as_deref(),
            Some(info.group_pubkey.as_str())
        );
        // Non-UTF-8 mnemonic bytes fail closed.
        assert!(matches!(
            mobile.create_account_from_mnemonic(vec![0xff, 0xfe], String::new(), "x".into()),
            Err(KeepMobileError::InvalidInput { .. })
        ));
    }

    #[test]
    fn get_seed_words_returns_stored_mnemonic_bytes() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let mnemonic = mobile.generate_mnemonic(12).unwrap();
        let expected = mnemonic.clone();
        let info = mobile
            .create_account_from_mnemonic(mnemonic, String::new(), "acct".into())
            .unwrap();

        // The seed is returned as the raw stored bytes, matching what was imported.
        assert_eq!(
            mobile.get_seed_words(info.group_pubkey).unwrap(),
            Some(expected)
        );
    }

    // A re-initialize that replaces a live node aborts the prior tasks and, like
    // invalidate_live_node, must drop its pending requests so the fresh node does
    // not surface sign requests from the torn-down session.
    #[test]
    fn retire_prior_node_tasks_clears_pending_when_replacing() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        // A drop-guard whose Drop only runs if the task's future is dropped, i.e.
        // the task was aborted. Detaching (dropping the JoinHandle without abort)
        // leaves the future running and never fires Drop, so this distinguishes a
        // real abort from a silently removed handle.abort().
        struct AbortFlag(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for AbortFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        seed_pending_request(&mobile);
        let aborted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let prior_flag = AbortFlag(Arc::clone(&aborted));
        mobile.runtime.block_on(async {
            // Stand in for a prior node's still-running task.
            mobile
                .node_tasks
                .lock()
                .unwrap()
                .push(tokio::spawn(async move {
                    let _flag = prior_flag;
                    std::future::pending::<()>().await;
                }));
            tokio::task::yield_now().await;

            mobile.retire_prior_node_tasks().await;

            // abort() is asynchronous; let the runtime cancel and drop the future.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert!(
                aborted.load(std::sync::atomic::Ordering::SeqCst),
                "prior node task must be aborted, not detached and left signing"
            );
            // Prior handles are drained; do_initialize installs the new ones next.
            assert!(mobile.node_tasks.lock().unwrap().is_empty());
        });
        assert_pending_cleared(&mobile);
    }

    // A first initialize with no prior node must leave pending requests untouched:
    // there is no torn-down session whose requests need dropping.
    #[test]
    fn retire_prior_node_tasks_keeps_pending_on_first_init() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        seed_pending_request(&mobile);
        mobile.runtime.block_on(async {
            mobile.retire_prior_node_tasks().await;

            assert_eq!(
                mobile.pending_requests.lock().await.len(),
                1,
                "first init must not drop pending requests"
            );
        });
    }

    // The import_share path lands in store_share_package, which got the same
    // invalidate_live_node() call; guard it so a future removal is caught.
    #[test]
    fn store_share_package_runs_node_teardown() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        seed_pending_request(&mobile);

        let key_bytes = Zeroizing::new(hex::decode("02".repeat(32)).unwrap());
        let (key_package, pubkey_package, vk_bytes) =
            KeepMobile::build_nsec_packages(&key_bytes).unwrap();
        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, "imported-share".into());
        let share = SharePackage::new(metadata, &key_package, &pubkey_package).unwrap();

        let info = mobile.store_share_package(&share).unwrap();

        assert_pending_cleared(&mobile);
        assert_eq!(
            storage.get_active_share_key().as_deref(),
            Some(info.group_pubkey.as_str())
        );
    }

    #[test]
    fn load_share_package_rejects_a_share_under_a_mismatched_key() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let key_bytes = Zeroizing::new(hex::decode("03".repeat(32)).unwrap());
        let (key_package, pubkey_package, vk_bytes) =
            KeepMobile::build_nsec_packages(&key_bytes).unwrap();
        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, "share".into());
        let share = SharePackage::new(metadata.clone(), &key_package, &pubkey_package).unwrap();
        let info = mobile.store_share_package(&share).unwrap();

        // Loaded under its own (correct) key: accepted.
        assert!(mobile.load_share_package().is_ok());

        // Simulate a compromised/buggy store returning this share under a
        // different key: the cryptographic identity no longer matches, so the
        // load must fail closed rather than use the wrong share.
        let raw = storage
            .load_share_by_key(info.group_pubkey.clone())
            .unwrap();
        let wrong_key = "ff".repeat(32);
        storage
            .store_share_by_key(wrong_key.clone(), raw, (&metadata).into())
            .unwrap();
        storage.set_active_share_key(Some(wrong_key)).unwrap();

        let result = mobile.load_share_package();
        assert!(
            matches!(&result, Err(KeepMobileError::InvalidShare { msg }) if msg.contains("does not match its group key")),
            "expected a group-key mismatch rejection"
        );
    }

    #[test]
    fn export_ncryptsec_accepts_utf8_password_bytes() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let key_bytes = Zeroizing::new(hex::decode("03".repeat(32)).unwrap());
        let (key_package, pubkey_package, vk_bytes) =
            KeepMobile::build_nsec_packages(&key_bytes).unwrap();
        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, "share".into());
        let share = SharePackage::new(metadata, &key_package, &pubkey_package).unwrap();
        mobile.store_share_package(&share).unwrap();
        let expected_secret = key_package.signing_share().serialize();

        let ncryptsec = mobile
            .export_ncryptsec("correct horse battery".as_bytes().to_vec())
            .unwrap();
        assert!(ncryptsec.starts_with("ncryptsec1"));

        // Round-trip: the password bytes must actually drive the encryption, so
        // decrypting with the same password recovers the signing share, and a
        // different password does not.
        let recovered =
            keep_core::keys::nip49::decrypt(&ncryptsec, "correct horse battery").unwrap();
        assert_eq!(recovered.as_slice(), expected_secret.as_slice());
        assert!(keep_core::keys::nip49::decrypt(&ncryptsec, "wrong password").is_err());
    }

    #[test]
    fn export_ncryptsec_rejects_non_utf8_password_bytes() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        let key_bytes = Zeroizing::new(hex::decode("03".repeat(32)).unwrap());
        let (key_package, pubkey_package, vk_bytes) =
            KeepMobile::build_nsec_packages(&key_bytes).unwrap();
        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, "share".into());
        let share = SharePackage::new(metadata, &key_package, &pubkey_package).unwrap();
        mobile.store_share_package(&share).unwrap();

        // 0xFF is never valid UTF-8: reject rather than silently mangle the password.
        let result = mobile.export_ncryptsec(vec![0xff, 0xfe]);
        assert!(
            matches!(&result, Err(KeepMobileError::InvalidInput { msg }) if msg.contains("UTF-8")),
            "expected an InvalidInput UTF-8 rejection, got {result:?}"
        );
    }
}

#[cfg(test)]
mod cert_pin_ffi_tests {
    use super::*;
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MemStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl SecureStorage for MemStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    fn keep() -> KeepMobile {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        KeepMobile::new(storage).unwrap()
    }

    fn pins_for(keep: &KeepMobile, host: &str) -> usize {
        keep.get_certificate_pins()
            .unwrap()
            .iter()
            .filter(|p| p.hostname == host)
            .count()
    }

    #[test]
    fn stage_then_retire_roundtrips_and_reports_unpinned() {
        let keep = keep();
        let host = "relay.example.com";
        let a = "a".repeat(64);
        let b = "b".repeat(64);

        keep.stage_certificate_pin(host.into(), a.clone()).unwrap();
        keep.stage_certificate_pin(host.into(), b.clone()).unwrap();
        assert_eq!(pins_for(&keep, host), 2);

        // Retiring one of two leaves the host pinned.
        let first = keep.remove_certificate_pin(host.into(), a).unwrap();
        assert!(first.pin_removed);
        assert!(!first.host_now_unpinned);
        assert_eq!(pins_for(&keep, host), 1);

        // Retiring the last pin reports the host is now unpinned.
        let last = keep.remove_certificate_pin(host.into(), b).unwrap();
        assert!(last.pin_removed);
        assert!(last.host_now_unpinned);
        assert!(keep.get_certificate_pins().unwrap().is_empty());
    }

    #[test]
    fn removing_absent_pin_reports_not_removed_and_still_pinned() {
        let keep = keep();
        let host = "relay.example.com";
        keep.stage_certificate_pin(host.into(), "a".repeat(64))
            .unwrap();

        let miss = keep
            .remove_certificate_pin(host.into(), "c".repeat(64))
            .unwrap();
        assert!(!miss.pin_removed);
        assert!(!miss.host_now_unpinned);
        assert_eq!(pins_for(&keep, host), 1);
    }

    #[test]
    fn stage_normalizes_hostname_to_verify_lookup_key() {
        let keep = keep();
        keep.stage_certificate_pin("WSS://Relay.Example.COM/".into(), "a".repeat(64))
            .unwrap();
        let pins = keep.get_certificate_pins().unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].hostname, "relay.example.com");
    }

    #[test]
    fn clear_removes_every_host() {
        let keep = keep();
        keep.stage_certificate_pin("relay.example.com".into(), "a".repeat(64))
            .unwrap();
        keep.stage_certificate_pin("other.example.com".into(), "b".repeat(64))
            .unwrap();
        keep.clear_certificate_pins().unwrap();
        assert!(keep.get_certificate_pins().unwrap().is_empty());
    }

    #[test]
    fn stage_rejects_non_hex_hash() {
        let keep = keep();
        assert!(keep
            .stage_certificate_pin("relay.example.com".into(), "not-a-hash".into())
            .is_err());
    }

    #[test]
    fn strict_cert_pinning_defaults_off_and_persists() {
        let keep = keep();
        assert!(
            !keep.get_strict_cert_pinning().unwrap(),
            "strict pinning is opt-in, off by default"
        );
        keep.set_strict_cert_pinning(true).unwrap();
        assert!(keep.get_strict_cert_pinning().unwrap());
        keep.set_strict_cert_pinning(false).unwrap();
        assert!(!keep.get_strict_cert_pinning().unwrap());
    }

    #[test]
    fn wss_relay_lacks_pin_tracks_pin_state() {
        let mut pins = keep_frost_net::CertificatePinSet::new();
        // An un-pinned wss relay lacks a pin (skipped in strict mode).
        assert!(super::wss_relay_lacks_pin("wss://relay.example.com", &pins));
        // After staging its pin (same host key), it no longer lacks one.
        pins.add_pin("relay.example.com".into(), [0xaa; 32]);
        assert!(!super::wss_relay_lacks_pin(
            "wss://relay.example.com",
            &pins
        ));
        // Non-wss and unparseable relays are not treated as pin-skips.
        assert!(!super::wss_relay_lacks_pin("ws://relay.example.com", &pins));
        assert!(!super::wss_relay_lacks_pin("not a url", &pins));
    }
}

#[cfg(test)]
mod restore_backup_metadata_tests {
    use super::*;
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// Records the metadata handed to the store, which the other mocks discard.
    /// Restore writes the backed-up flag in two places, the metadata passed to
    /// storage and the metadata serialized into the record, so a test reading
    /// only one of them can pass while the other is still wrong.
    #[derive(Default)]
    struct RecordingStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
        metas: StdMutex<Vec<ShareMetadataInfo>>,
        active: StdMutex<Option<String>>,
    }

    impl SecureStorage for RecordingStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            meta: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().insert(key, data);
            self.metas.lock().unwrap().push(meta);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            self.metas.lock().unwrap().clone()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            self.active.lock().unwrap().clone()
        }
        fn set_active_share_key(&self, key: Option<String>) -> Result<(), KeepMobileError> {
            *self.active.lock().unwrap() = key;
            Ok(())
        }
    }

    fn backup_share(did_backup: bool) -> keep_core::backup::BackupShare {
        keep_core::backup::BackupShare {
            identifier: 1,
            threshold: 2,
            total_shares: 3,
            group_pubkey: hex::encode([7u8; 32]),
            name: "restored".into(),
            created_at: 1_700_000_000,
            last_used: None,
            sign_count: 0,
            did_backup,
            // Restore hex-decodes these and stores the bytes without parsing
            // them, so opaque values exercise the metadata path fine.
            key_package: hex::encode([1u8; 48]),
            pubkey_package: hex::encode([2u8; 48]),
            ciphersuite: Default::default(),
            group_subkey_secret: None,
        }
    }

    // A descriptor write that fails must leave nothing behind, because only the
    // share and key writes are covered by the duplicate guard: a failure after
    // them is terminal, since the retry finds the shares it wrote and refuses.
    // Running the descriptors first is what makes the retry work.
    #[test]
    fn a_failed_descriptor_write_leaves_a_restore_retryable() {
        struct IndexUnwritableStorage {
            inner: RecordingStorage,
            block_index: StdMutex<bool>,
        }

        impl SecureStorage for IndexUnwritableStorage {
            fn store_share(&self, d: Vec<u8>, m: ShareMetadataInfo) -> Result<(), KeepMobileError> {
                self.inner.store_share(d, m)
            }
            fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
                self.inner.load_share()
            }
            fn has_share(&self) -> bool {
                self.inner.has_share()
            }
            fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
                self.inner.get_share_metadata()
            }
            fn delete_share(&self) -> Result<(), KeepMobileError> {
                self.inner.delete_share()
            }
            fn store_share_by_key(
                &self,
                k: String,
                d: Vec<u8>,
                m: ShareMetadataInfo,
            ) -> Result<(), KeepMobileError> {
                if k == DESCRIPTOR_INDEX_KEY && *self.block_index.lock().unwrap() {
                    return Err(KeepMobileError::StorageError {
                        msg: "cannot write the descriptor index".into(),
                    });
                }
                self.inner.store_share_by_key(k, d, m)
            }
            fn load_share_by_key(&self, k: String) -> Result<Vec<u8>, KeepMobileError> {
                self.inner.load_share_by_key(k)
            }
            fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
                self.inner.list_all_shares()
            }
            fn delete_share_by_key(&self, k: String) -> Result<(), KeepMobileError> {
                self.inner.delete_share_by_key(k)
            }
            fn get_active_share_key(&self) -> Option<String> {
                self.inner.get_active_share_key()
            }
            fn set_active_share_key(&self, k: Option<String>) -> Result<(), KeepMobileError> {
                self.inner.set_active_share_key(k)
            }
        }

        let group = [7u8; 32];
        let bytes = keep_core::backup::create_backup_from_data(
            vec![],
            vec![backup_share(false)],
            vec![keep_core::wallet::WalletDescriptor {
                group_pubkey: group,
                external_descriptor: "wpkh(xpub.../0/*)".into(),
                internal_descriptor: "wpkh(xpub.../1/*)".into(),
                network: "bitcoin".into(),
                created_at: 1_700_000_000,
                device_registrations: vec![],
                policy_hash: [9u8; 32],
                version: 1,
                previous_descriptor_hash: None,
                policy: None,
            }],
            vec![],
            vec![],
            keep_core::backup::BackupConfig {
                kill_switch: false,
                proxy: None,
            },
            vec![],
            "correct horse battery staple",
        )
        .expect("backup should build");

        let faulty = Arc::new(IndexUnwritableStorage {
            inner: RecordingStorage::default(),
            block_index: StdMutex::new(true),
        });
        let storage: Arc<dyn SecureStorage> = faulty.clone();
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();

        mobile
            .restore_backup(bytes.clone(), "correct horse battery staple".into())
            .expect_err("the descriptor write fails");
        assert!(
            storage.load_share_by_key(hex::encode(group)).is_err(),
            "no share may land before the descriptors, or the duplicate guard \
             makes the retry terminal"
        );

        *faulty.block_index.lock().unwrap() = false;
        mobile
            .restore_backup(bytes, "correct horse battery staple".into())
            .expect("the retry completes the restore");
        assert!(storage.load_share_by_key(hex::encode(group)).is_ok());
    }

    fn restore_one(did_backup: bool) -> (Arc<RecordingStorage>, String) {
        let bytes = keep_core::backup::create_backup_from_data(
            vec![],
            vec![backup_share(did_backup)],
            vec![],
            vec![],
            vec![],
            keep_core::backup::BackupConfig {
                kill_switch: false,
                proxy: None,
            },
            vec![],
            "correct horse battery staple",
        )
        .expect("backup should build");

        let storage = Arc::new(RecordingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        mobile
            .restore_backup(bytes, "correct horse battery staple".into())
            .expect("restore should succeed");

        let key = hex::encode([7u8; 32]);
        let raw = storage.load_share_by_key(key).expect("share stored");
        let stored: StoredShareData = serde_json::from_slice(&raw).expect("record parses");
        (Arc::clone(&storage), stored.metadata_json)
    }

    /// Selects by group key rather than name: non-share records such as the
    /// policy and any descriptors are persisted through the same storage method,
    /// so the recorded metadata is not a single entry, and a name is
    /// user-controlled data that a future record could collide with.
    fn restored_share_meta(storage: &RecordingStorage) -> ShareMetadataInfo {
        storage
            .metas
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.group_pubkey == [7u8; 32])
            .cloned()
            .expect("the restored share's metadata should reach storage")
    }

    #[test]
    fn a_share_that_was_not_backed_up_does_not_come_back_marked_backed_up() {
        let (storage, metadata_json) = restore_one(false);

        let recorded: keep_core::frost::ShareMetadata =
            serde_json::from_str(&metadata_json).expect("record parses");
        assert!(
            !recorded.did_backup,
            "record should keep the recorded flag, got: {metadata_json}"
        );
        assert!(
            !restored_share_meta(&storage).did_backup,
            "the metadata handed to storage must agree with the record"
        );
    }

    #[test]
    fn a_share_that_was_backed_up_stays_marked_backed_up() {
        let (storage, metadata_json) = restore_one(true);

        let recorded: keep_core::frost::ShareMetadata =
            serde_json::from_str(&metadata_json).expect("record parses");
        assert!(
            recorded.did_backup,
            "a true flag must survive too, or the fix would just invert the bug: {metadata_json}"
        );
        assert!(restored_share_meta(&storage).did_backup);
    }
}

#[cfg(test)]
mod sign_request_mapping_tests {
    use super::*;

    fn session_with_payload(
        message_type: &str,
        requester: u16,
        structured_payload: Option<Vec<u8>>,
    ) -> keep_frost_net::SessionInfo {
        keep_frost_net::SessionInfo {
            structured_payload,
            ..session(message_type, requester)
        }
    }

    fn session(message_type: &str, requester: u16) -> keep_frost_net::SessionInfo {
        keep_frost_net::SessionInfo {
            session_id: [9u8; 32],
            message: vec![0xab; 32],
            threshold: 2,
            participants: vec![1, 2, 3],
            requester,
            message_type: message_type.into(),
            structured_payload: None,
            derivation_path: vec![],
            taproot_tweak: None,
        }
    }

    #[test]
    fn the_label_reaches_the_approval_request() {
        // Without this the Android summary falls back to an empty string and the
        // user approves 32 bytes with nothing saying which domain they belong to.
        let req = sign_request_from_session(&session("nostr-event", 3));
        assert_eq!(req.message_type, "nostr-event");
    }

    #[test]
    fn a_newline_cannot_add_lines_to_the_prompt() {
        // The notification renders the summary as multi-line text, so an
        // embedded newline would let the requester append their own lines
        // beneath the real one.
        let req = sign_request_from_session(&session("nostr-event\nApproved by Keep", 1));
        assert!(
            !req.message_type.contains('\n'),
            "got: {:?}",
            req.message_type
        );
    }

    #[test]
    fn a_bidi_override_cannot_rewrite_the_text_around_it() {
        let req = sign_request_from_session(&session("nostr\u{202E}drowssap", 1));
        assert!(
            !req.message_type.contains('\u{202E}'),
            "got: {:?}",
            req.message_type
        );
    }

    #[test]
    fn an_overlong_label_cannot_crowd_out_the_rest_of_the_prompt() {
        let req = sign_request_from_session(&session(&"A".repeat(64), 1));
        assert!(
            req.message_type.chars().count() <= MESSAGE_TYPE_DISPLAY_MAX + 3,
            "got {} chars",
            req.message_type.chars().count()
        );
    }

    #[test]
    fn an_ordinary_label_survives_sanitizing_intact() {
        // The stripping must not eat the normal case it exists to display.
        let req = sign_request_from_session(&session("bitcoin-sighash", 1));
        assert_eq!(req.message_type, "bitcoin-sighash");
    }

    #[test]
    fn a_request_without_a_structured_body_is_not_verified() {
        // Nothing checked the label, so surfaces must not present it as settled.
        let req = sign_request_from_session(&session("nostr-event", 1));
        assert!(!req.type_verified);
    }

    #[test]
    fn a_request_with_a_structured_body_is_verified() {
        // Reaching this point with a body attached means the responder already
        // recomputed the digest from it and matched the signed bytes; a mismatch
        // or an unknown label is refused before the hook runs.
        let req = sign_request_from_session(&session_with_payload(
            "bitcoin-sighash",
            1,
            Some(b"{}".to_vec()),
        ));
        assert!(req.type_verified);
    }

    #[test]
    fn the_untouched_fields_are_untouched() {
        // Pins the half of the extraction that was meant to be behaviour-preserving.
        let s = session("nostr-event", 2);
        let req = sign_request_from_session(&s);
        assert_eq!(req.id, hex::encode(s.session_id));
        assert_eq!(req.session_id, s.session_id.to_vec());
        assert!(req.metadata.is_none());
    }

    #[test]
    fn the_requesting_peer_reaches_the_approval_request() {
        let req = sign_request_from_session(&session("nostr-event", 4));
        assert_eq!(req.from_peer, 4, "the approver needs to know who asked");
    }

    #[test]
    fn the_preview_is_bounded_and_hex() {
        let req = sign_request_from_session(&session("nostr-event", 1));
        // Eight bytes rendered as hex, not the whole digest.
        assert_eq!(req.message_preview.len(), 16);
        assert!(req.message_preview.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[cfg(test)]
mod baseline_presign_policy_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// Storage whose only job is to answer the kill-switch read. Seeded
    /// directly rather than through `store_share_by_key`, which requires share
    /// metadata that has nothing to do with a boolean.
    struct KillSwitchOffStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl KillSwitchOffStorage {
        fn with_switch_off() -> Self {
            let mut data = HashMap::new();
            data.insert(
                KILL_SWITCH_STORAGE_KEY.to_string(),
                serde_json::to_vec(&false).expect("bool serialises"),
            );
            Self {
                data: StdMutex::new(data),
            }
        }
    }

    impl SecureStorage for KillSwitchOffStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, _: String) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    fn session_with(message_type: &str, message: Vec<u8>) -> SessionInfo {
        SessionInfo {
            session_id: [9u8; 32],
            message,
            threshold: 2,
            participants: vec![1, 2],
            requester: 1,
            message_type: message_type.to_string(),
            structured_payload: None,
            derivation_path: Vec::new(),
            taproot_tweak: None,
        }
    }

    /// The baseline policy has to run before the pre-approval short-circuit, and
    /// this is the case that tells the two placements apart. A pre-approval
    /// records that the user accepted one specific set of bytes; it does not
    /// record consent to sign an unstructured request, and a policy sitting
    /// below the short-circuit would never be consulted for one. Move the
    /// policy call after `consume_pre_approval` and this test fails, which is
    /// the point of writing it this way round rather than testing an
    /// unapproved request that would be refused at the prompt anyway.
    #[test]
    fn raw_label_is_refused_even_when_already_pre_approved() {
        // An unreadable switch counts as engaged, so it has to be explicitly
        // off or this passes for the wrong reason: every request refused, and
        // nothing proven about the policy under test.
        let storage = KillSwitchOffStorage::with_switch_off();

        let message = vec![7u8; 32];
        let pre_approved: PreApprovedHashes = Arc::new(StdMutex::new(HashMap::new()));
        {
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(&message).into();
            pre_approved
                .lock()
                .unwrap()
                .insert(hash, std::time::Instant::now());
        }

        let (request_tx, _request_rx) = mpsc::channel(1);
        let hooks = MobileSigningHooks {
            request_tx,
            pre_approved_hashes: pre_approved,
            storage: Arc::new(storage),
        };

        let err = hooks
            .pre_sign(&session_with("raw", message.clone()))
            .expect_err("a raw request must be refused even with a pre-approval recorded");
        assert!(
            format!("{err}").contains("raw"),
            "refusal should name the policy that fired, got: {err}"
        );
    }

    /// The gap a denylist leaves. An empty label is not "raw", so the string
    /// comparison misses it, and the approval surface drops a blank label
    /// along with the "claimed:" qualifier that would have marked it
    /// unverified. Before this guard the request carrying no stated domain at
    /// all rendered with fewer warnings than one that admitted to being raw.
    #[test]
    fn a_label_that_would_display_as_blank_is_refused() {
        for label in ["", "   ", "\u{200b}", " \u{200b} "] {
            let storage = KillSwitchOffStorage::with_switch_off();
            let (request_tx, _request_rx) = mpsc::channel(1);
            let hooks = MobileSigningHooks {
                request_tx,
                pre_approved_hashes: Arc::new(StdMutex::new(HashMap::new())),
                storage: Arc::new(storage),
            };
            let err = hooks
                .pre_sign(&session_with(label, vec![1u8; 32]))
                .expect_err("a label that displays as blank must be refused");
            assert!(
                format!("{err}").contains("blank"),
                "expected the blank-label refusal for {label:?}, got: {err}"
            );
        }
    }

    /// The check and the display have to agree on what the label says. The
    /// upstream policy compares the untouched string while the prompt strips
    /// zero-width characters, so this value evades the comparison and still
    /// renders as "raw".
    #[test]
    fn raw_with_a_zero_width_character_is_refused() {
        let storage = KillSwitchOffStorage::with_switch_off();
        let (request_tx, _request_rx) = mpsc::channel(1);
        let hooks = MobileSigningHooks {
            request_tx,
            pre_approved_hashes: Arc::new(StdMutex::new(HashMap::new())),
            storage: Arc::new(storage),
        };
        let err = hooks
            .pre_sign(&session_with("raw\u{200b}", vec![2u8; 32]))
            .expect_err("a label displaying as raw must be refused however it is spelled");
        assert!(
            format!("{err}").contains("raw"),
            "refusal should name the policy that fired, got: {err}"
        );
    }

    /// A raw request with no pre-approval. Less about coverage than about
    /// failing fast: delete the policy and this path falls through to the
    /// interactive prompt, where the send succeeds and the test then waits out
    /// the full response timeout instead of failing. A regression that stalls
    /// the suite is harder to read than one that fails.
    #[test]
    fn raw_without_a_pre_approval_is_refused_rather_than_prompted() {
        let storage = KillSwitchOffStorage::with_switch_off();
        let (request_tx, _request_rx) = mpsc::channel(1);
        let hooks = MobileSigningHooks {
            request_tx,
            pre_approved_hashes: Arc::new(StdMutex::new(HashMap::new())),
            storage: Arc::new(storage),
        };
        hooks
            .pre_sign(&session_with("raw", vec![4u8; 32]))
            .expect_err("a raw request must be refused without reaching the prompt");
    }

    /// The guard must not swallow the requests it exists to let through: a
    /// pre-approved request carrying an ordinary label still short-circuits.
    /// Without this, refusing everything would satisfy the test above.
    #[test]
    fn a_pre_approved_ordinary_request_still_passes() {
        let storage = KillSwitchOffStorage::with_switch_off();

        let message = vec![3u8; 32];
        let pre_approved: PreApprovedHashes = Arc::new(StdMutex::new(HashMap::new()));
        {
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(&message).into();
            pre_approved
                .lock()
                .unwrap()
                .insert(hash, std::time::Instant::now());
        }

        let (request_tx, _request_rx) = mpsc::channel(1);
        let hooks = MobileSigningHooks {
            request_tx,
            pre_approved_hashes: pre_approved,
            storage: Arc::new(storage),
        };

        hooks
            .pre_sign(&session_with(
                keep_frost_net::MSG_TYPE_BITCOIN_SIGHASH,
                message,
            ))
            .expect("a pre-approved request with an ordinary label must still pass");
    }
}

#[cfg(test)]
mod dkg_pending_share_tests {
    use super::*;
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;

    /// Secure storage that can be told to fail writes for real share records
    /// (any key not using the reserved `__keep_` namespace), modelling the
    /// full-store / encrypted-write failure that drops a completed DKG share.
    #[derive(Default)]
    struct FailingShareStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
        active: StdMutex<Option<String>>,
        fail_shares: AtomicBool,
    }

    impl SecureStorage for FailingShareStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            if !key.starts_with("__keep_") && self.fail_shares.load(Ordering::Relaxed) {
                return Err(KeepMobileError::StorageError {
                    msg: "simulated full store".into(),
                });
            }
            self.data.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            self.data
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            self.active.lock().unwrap().clone()
        }
        fn set_active_share_key(&self, key: Option<String>) -> Result<(), KeepMobileError> {
            *self.active.lock().unwrap() = key;
            Ok(())
        }
    }

    /// Build a valid passphrase-encrypted share export string, as a completed
    /// DKG would hand to `import_share`.
    fn share_export(passphrase: &str, name: &str) -> String {
        let key_bytes = Zeroizing::new(hex::decode("07".repeat(32)).unwrap());
        let (key_package, pubkey_package, vk_bytes) =
            KeepMobile::build_nsec_packages(&key_bytes).unwrap();
        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, name.into());
        let share = SharePackage::new(metadata, &key_package, &pubkey_package).unwrap();
        ShareExport::from_share(&share, passphrase)
            .unwrap()
            .to_json()
            .unwrap()
    }

    /// Stash a share the manual-QR way: the user knows the passphrase, so the
    /// secret carries none and the marker records `vault_protected = false`.
    fn stash_passphrase_protected(
        storage: &Arc<dyn SecureStorage>,
        export: &str,
        name: &str,
        group: &str,
    ) {
        persistence::persist_pending_dkg_secret(
            storage,
            DKG_PENDING_SECRET_KEY,
            &persistence::PendingDkgSecret {
                schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                share_export: Zeroizing::new(export.into()),
                vault_passphrase: None,
            },
        )
        .unwrap();
        persistence::persist_pending_dkg_marker(
            storage,
            DKG_PENDING_MARKER_KEY,
            &persistence::PendingDkgMarker {
                schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                name: name.into(),
                group_pubkey_hex: group.into(),
                vault_protected: false,
            },
        )
        .unwrap();
    }

    // The DKG path stashes its ephemeral passphrase inside the auth-gated secret
    // and marks the stash vault-protected. Recovery must then complete from the
    // vault alone — `recover_dkg_share(None)` — with no user-supplied passphrase,
    // which is the whole point of keep-6ik (the ceremony passphrase is never
    // shown or stored anywhere the user could re-enter it).
    #[test]
    fn vault_protected_stash_recovers_without_a_supplied_passphrase() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        let passphrase = "f00dbabe".repeat(8); // stand-in for the 256-bit ceremony secret
        let name = "vault-share";
        let export = share_export(&passphrase, name);

        persistence::persist_pending_dkg_secret(
            &(storage.clone() as Arc<dyn SecureStorage>),
            DKG_PENDING_SECRET_KEY,
            &persistence::PendingDkgSecret {
                schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                share_export: Zeroizing::new(export),
                vault_passphrase: Some(Zeroizing::new(passphrase)),
            },
        )
        .unwrap();
        persistence::persist_pending_dkg_marker(
            &(storage.clone() as Arc<dyn SecureStorage>),
            DKG_PENDING_MARKER_KEY,
            &persistence::PendingDkgMarker {
                schema_version: persistence::DKG_STASH_SCHEMA_VERSION,
                name: name.into(),
                group_pubkey_hex: "cafe".into(),
                vault_protected: true,
            },
        )
        .unwrap();

        // The marker surfaces the protection mode without a vault unlock.
        let pending = mobile.pending_dkg_share().unwrap().unwrap();
        assert!(pending.vault_protected);

        // No passphrase supplied: recovery draws it from the vault-decrypted secret.
        let info = mobile
            .recover_dkg_share(None)
            .expect("vault-protected recovery must not need a supplied passphrase");
        assert_eq!(info.name, name);
        assert!(mobile.pending_dkg_share().unwrap().is_none());
        assert!(mobile.get_active_share().is_some());
    }

    // A storage failure during the post-ceremony import must leave the finalized
    // share export durably stashed (never silently dropped), and a later
    // `recover_dkg_share` must complete the import and clear the stash.
    #[test]
    fn stash_survives_import_failure_and_recovers() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        let passphrase = "correct horse battery staple";
        let name = "ceremony-share";
        let export = share_export(passphrase, name);

        // Reproduce `frost_run_dkg`'s post-ceremony path: stash first, then let
        // the import fail the way a full store would.
        storage.fail_shares.store(true, Ordering::Relaxed);
        stash_passphrase_protected(
            &(storage.clone() as Arc<dyn SecureStorage>),
            &export,
            name,
            "deadbeef",
        );
        let import = mobile.import_share(export, passphrase.into(), name.into());
        assert!(
            import.is_err(),
            "import must fail under the simulated full store"
        );

        // The share is not lost: it is surfaced as pending for recovery.
        let pending = mobile
            .pending_dkg_share()
            .expect("loading the stash must not error")
            .expect("a failed import must leave a recoverable stash");
        assert_eq!(pending.name, name);
        assert_eq!(pending.group_pubkey, "deadbeef");

        // Storage recovers; finishing the import stores the share and clears the
        // stash so it is not replayed.
        storage.fail_shares.store(false, Ordering::Relaxed);
        let info = mobile
            .recover_dkg_share(Some(passphrase.into()))
            .expect("recovery must complete the import once storage is healthy");
        assert_eq!(info.name, name);
        assert!(
            mobile.pending_dkg_share().unwrap().is_none(),
            "a completed recovery must clear the stash"
        );
        assert!(
            mobile.get_active_share().is_some(),
            "the recovered share must be stored and active"
        );
    }

    // `frost_cancel_dkg` must target a run by id: a stale id for a run that has
    // since finished must not flip a later run's cancel flag (§8, GH #969).
    #[test]
    fn cancel_targets_run_by_id() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>).unwrap();

        // Register run 1 the way `frost_run_dkg` does.
        let cancel1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *mobile.dkg_active.lock().unwrap() = Some(DkgActiveRun {
            id: 1,
            cancel: cancel1.clone(),
        });

        // A cancel for a different (already-finished) run is ignored.
        mobile.frost_cancel_dkg(2);
        assert!(
            !cancel1.load(std::sync::atomic::Ordering::Relaxed),
            "a mismatched run id must not cancel the active run"
        );

        // A cancel for the active run flips its flag.
        mobile.frost_cancel_dkg(1);
        assert!(
            cancel1.load(std::sync::atomic::Ordering::Relaxed),
            "the matching run id must cancel the active run"
        );

        // Simulate run 1 finishing (guard deregisters) and run 2 starting fresh.
        let cancel2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *mobile.dkg_active.lock().unwrap() = Some(DkgActiveRun {
            id: 2,
            cancel: cancel2.clone(),
        });

        // The stale cancel for run 1 must not touch run 2.
        mobile.frost_cancel_dkg(1);
        assert!(
            !cancel2.load(std::sync::atomic::Ordering::Relaxed),
            "a cancel for a finished run must not abort the next run"
        );

        // With no active run, a cancel is a harmless no-op.
        *mobile.dkg_active.lock().unwrap() = None;
        mobile.frost_cancel_dkg(2);
    }

    // `frost_dkg_begin` stashes a per-group subkey secret; an abandoned begin
    // (never followed by `frost_run_dkg`) must be discardable so it can't
    // accumulate for the process lifetime (GH #970).
    #[test]
    fn discard_drops_pending_dkg_subkey() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>).unwrap();

        mobile.frost_dkg_begin("group-a".into()).unwrap();
        mobile.frost_dkg_begin("group-b".into()).unwrap();
        assert_eq!(mobile.dkg_subkeys.lock().unwrap().len(), 2);

        // Discarding one abandoned begin drops only that group's subkey.
        mobile.frost_dkg_discard("group-a".into());
        let map = mobile.dkg_subkeys.lock().unwrap();
        assert!(!map.contains_key("group-a"));
        assert!(map.contains_key("group-b"));
        drop(map);

        // Discarding a group with no pending subkey is a harmless no-op.
        mobile.frost_dkg_discard("group-a".into());
        assert_eq!(mobile.dkg_subkeys.lock().unwrap().len(), 1);
    }

    // A preflight failure in `frost_run_dkg` (here: no relay clears TLS pinning,
    // failing before the ceremony starts) must leave the pending subkey stashed
    // so the run can be retried without re-minting — which would otherwise force
    // a fresh roster across every participant.
    #[test]
    fn run_dkg_preflight_failure_retains_pending_subkey() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>).unwrap();

        struct NoopProgress;
        impl dkg::DkgProgressCallback for NoopProgress {
            fn on_progress(&self, _: DkgProgressUpdate) {}
        }

        mobile.frost_dkg_begin("group-a".into()).unwrap();

        // Empty relay set: nothing passes TLS pinning, so `frost_run_dkg` fails
        // in preflight, before any ceremony network I/O.
        let config = DkgConfig {
            group_name: "group-a".into(),
            threshold: 2,
            participants: 3,
            our_index: 1,
            relays: Vec::new(),
            roster: Vec::new(),
        };
        let err = mobile
            .frost_run_dkg(
                config,
                "group-a-share".into(),
                "pass".into(),
                30,
                Arc::new(NoopProgress),
            )
            .expect_err("a run with no verifiable relay must fail in preflight");
        assert!(
            matches!(err, KeepMobileError::NetworkError { .. }),
            "expected a network/transport error, got {err:?}"
        );

        // The subkey survives the failed preflight, so a retry needs no re-mint.
        assert!(mobile.dkg_subkeys.lock().unwrap().contains_key("group-a"));
    }

    // A wrong passphrase must not clear the stash: the share stays recoverable.
    #[test]
    fn failed_recovery_retains_stash() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        let export = share_export("right-pass", "share");
        stash_passphrase_protected(
            &(storage.clone() as Arc<dyn SecureStorage>),
            &export,
            "share",
            "abc123",
        );

        assert!(mobile.recover_dkg_share(Some("wrong-pass".into())).is_err());
        assert!(
            mobile.pending_dkg_share().unwrap().is_some(),
            "a failed recovery must keep the share recoverable"
        );
    }

    // With nothing stashed, recovery reports there is nothing to do.
    #[test]
    fn recover_without_pending_share_errors() {
        let storage: Arc<dyn SecureStorage> = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage).unwrap();
        assert!(mobile.pending_dkg_share().unwrap().is_none());
        assert!(mobile.recover_dkg_share(Some("pass".into())).is_err());
    }

    // A new DKG run must refuse to start while an earlier share is still pending
    // recovery, so its completion can't overwrite the single-slot stash and lose
    // the earlier share. The reject happens in pre-flight, before any network I/O.
    #[test]
    fn run_dkg_rejected_while_share_pending_recovery() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        stash_passphrase_protected(
            &(storage.clone() as Arc<dyn SecureStorage>),
            &share_export("pass", "prior"),
            "prior",
            "abc123",
        );

        struct NoopProgress;
        impl dkg::DkgProgressCallback for NoopProgress {
            fn on_progress(&self, _: DkgProgressUpdate) {}
        }

        let config = DkgConfig {
            group_name: "new-group".into(),
            threshold: 2,
            participants: 3,
            our_index: 1,
            relays: vec!["wss://relay.example".into()],
            roster: Vec::new(),
        };
        let err = mobile
            .frost_run_dkg(
                config,
                "new-share".into(),
                "pass".into(),
                30,
                Arc::new(NoopProgress),
            )
            .expect_err("a new run must be refused while a share is pending recovery");
        assert!(
            matches!(err, KeepMobileError::StorageError { .. }),
            "expected a storage error, got {err:?}"
        );

        // The prior stash is untouched and still recoverable.
        assert!(mobile.pending_dkg_share().unwrap().is_some());
    }

    // A corrupt stash must surface as an error, not be masked as "nothing
    // pending" — otherwise a live share would look absent and never recover.
    #[test]
    fn unreadable_stash_surfaces_as_error() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        storage
            .store_share_by_key(
                DKG_PENDING_MARKER_KEY.into(),
                b"not valid json".to_vec(),
                ShareMetadataInfo {
                    name: "dkg_pending".into(),
                    identifier: 0,
                    threshold: 0,
                    total_shares: 0,
                    group_pubkey: Vec::new(),
                    did_backup: false,
                },
            )
            .unwrap();

        assert!(
            mobile.pending_dkg_share().is_err(),
            "a corrupt stash must not be reported as nothing pending"
        );
    }

    // An unrecoverable stash (its ceremony passphrase is gone, or it is corrupt)
    // must not brick group creation for good: discarding it clears the stash and
    // lets the pending guard pass again. Discard is also idempotent.
    #[test]
    fn discard_clears_unrecoverable_stash() {
        let storage = Arc::new(FailingShareStorage::default());
        let mobile = KeepMobile::new(storage.clone() as Arc<dyn SecureStorage>).unwrap();

        // Nothing pending: discard is a no-op that still succeeds.
        mobile.discard_pending_dkg_share().unwrap();

        // A corrupt stash refuses new runs (guard fails closed on load error) and
        // cannot be recovered; without discard the device is stuck here.
        storage
            .store_share_by_key(
                DKG_PENDING_MARKER_KEY.into(),
                b"not valid json".to_vec(),
                ShareMetadataInfo {
                    name: "dkg_pending".into(),
                    identifier: 0,
                    threshold: 0,
                    total_shares: 0,
                    group_pubkey: Vec::new(),
                    did_backup: false,
                },
            )
            .unwrap();
        assert!(mobile.pending_dkg_share().is_err());

        mobile.discard_pending_dkg_share().unwrap();

        // Stash gone: the guard reports nothing pending, so a new run is unblocked.
        assert!(mobile.pending_dkg_share().unwrap().is_none());
    }
}

#[cfg(test)]
mod velocity_fault_tests {
    use super::*;
    use crate::storage::{SecureStorage, ShareMetadataInfo};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    // Reads of `unreadable` fault rather than report absence, which is the
    // distinction the fix turns on: an absent record is a history of nothing,
    // a faulted one is a history we do not know.
    #[derive(Default)]
    struct FaultingStorage {
        records: StdMutex<HashMap<String, Vec<u8>>>,
        unreadable: StdMutex<Vec<String>>,
        unwritable: StdMutex<Vec<String>>,
        undeletable: StdMutex<Vec<String>>,
        reads: StdMutex<HashMap<String, usize>>,
    }

    impl FaultingStorage {
        fn fault(&self, key: &str) {
            self.unreadable.lock().unwrap().push(key.into());
        }

        fn fault_write(&self, key: &str) {
            self.unwritable.lock().unwrap().push(key.into());
        }

        fn heal(&self) {
            self.unreadable.lock().unwrap().clear();
            self.unwritable.lock().unwrap().clear();
        }

        fn fault_delete(&self, key: &str) {
            self.undeletable.lock().unwrap().push(key.into());
        }

        /// How many reads of `key` the backend has served, for pinning that a
        /// permanent fault is not re-read on every decision.
        fn reads_of(&self, key: &str) -> usize {
            *self.reads.lock().unwrap().get(key).unwrap_or(&0)
        }

        fn plant(&self, key: &str, data: Vec<u8>) {
            self.records.lock().unwrap().insert(key.into(), data);
        }

        fn raw(&self, key: &str) -> Option<Vec<u8>> {
            self.records.lock().unwrap().get(key).cloned()
        }
    }

    impl SecureStorage for FaultingStorage {
        fn store_share(&self, _: Vec<u8>, _: ShareMetadataInfo) -> Result<(), KeepMobileError> {
            unimplemented!()
        }
        fn load_share(&self) -> Result<Vec<u8>, KeepMobileError> {
            Err(KeepMobileError::StorageNotFound)
        }
        fn has_share(&self) -> bool {
            false
        }
        fn get_share_metadata(&self) -> Option<ShareMetadataInfo> {
            None
        }
        fn delete_share(&self) -> Result<(), KeepMobileError> {
            Ok(())
        }
        fn store_share_by_key(
            &self,
            key: String,
            data: Vec<u8>,
            _: ShareMetadataInfo,
        ) -> Result<(), KeepMobileError> {
            if self.unwritable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot write right now".into(),
                });
            }
            self.records.lock().unwrap().insert(key, data);
            Ok(())
        }
        fn load_share_by_key(&self, key: String) -> Result<Vec<u8>, KeepMobileError> {
            *self.reads.lock().unwrap().entry(key.clone()).or_insert(0) += 1;
            if self.unreadable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot decrypt right now".into(),
                });
            }
            self.records
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(KeepMobileError::StorageNotFound)
        }
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            Vec::new()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            if self.undeletable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot delete right now".into(),
                });
            }
            self.records.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            None
        }
        fn set_active_share_key(&self, _: Option<String>) -> Result<(), KeepMobileError> {
            Ok(())
        }
    }

    // The constructor used to propagate this read fault, and keep-android
    // builds KeepMobile before it assigns anything, so the throw left the app
    // with no account switcher, no import, no export and no kill switch, every
    // launch, because the same read faults every time. Its neighbours in the
    // constructor already degraded instead.
    #[test]
    fn an_unreadable_velocity_record_still_opens_the_app() {
        let storage = Arc::new(FaultingStorage::default());
        storage.fault(VELOCITY_STORAGE_KEY);

        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>)
            .expect("an unreadable velocity record must not stop the app opening");
        assert!(mobile.velocity_lock().unwrap().is_none());
    }

    // Degrading is only safe because the counters stay unknown: recording into
    // them is refused rather than silently starting a fresh history, and
    // clearing them is the deliberate way back.
    #[test]
    fn clearing_the_counters_recovers_from_an_unreadable_record() {
        let storage = Arc::new(FaultingStorage::default());
        storage.fault(VELOCITY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(mobile.record_policy_transaction(1_000).is_err());
        assert!(storage.raw(VELOCITY_STORAGE_KEY).is_none());

        mobile.clear_velocity_tracker().unwrap();

        let stored = storage
            .raw(VELOCITY_STORAGE_KEY)
            .expect("clearing must overwrite the unreadable record");
        assert!(VelocityTracker::from_bytes(&stored).is_ok());
        mobile.record_policy_transaction(1_000).unwrap();
        assert_eq!(
            mobile
                .velocity_lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .daily_total(),
            1_000
        );
    }
    // The recovery path must not half-complete. A Keystore that cannot decrypt
    // the record is the same fault class as one that cannot write it, so these
    // two arrive together: if clearing flipped the counters to known-empty and
    // then failed to persist, the refusal would be lifted for the rest of the
    // process against a history that is still unknown, which is the fail-open
    // the refusal exists to close, reached through its own recovery.
    #[test]
    fn a_clear_that_cannot_be_persisted_leaves_the_counters_unknown() {
        let storage = Arc::new(FaultingStorage::default());
        storage.fault(VELOCITY_STORAGE_KEY);
        storage.fault_write(VELOCITY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(mobile.clear_velocity_tracker().is_err());
        assert!(
            mobile.velocity_lock().unwrap().is_none(),
            "a failed clear must not leave the counters reading as empty"
        );
    }
    // A Keystore decrypt failure can be transient with the record intact, so
    // the refusal must not outlast its cause and must not cost the history to
    // leave. The retry recovers the real counters, which clearing cannot.
    #[test]
    fn counters_that_become_readable_again_are_the_real_ones() {
        let storage = Arc::new(FaultingStorage::default());
        let mut seeded = VelocityTracker::new();
        seeded.record(5_000);
        storage.plant(VELOCITY_STORAGE_KEY, seeded.to_bytes().unwrap());
        storage.fault(VELOCITY_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(mobile.velocity_lock().unwrap().is_none());

        storage.heal();
        mobile
            .evaluate_policy(TransactionContext {
                amount_sats: 1,
                fee_sats: 1,
                destinations: vec![],
                has_unknown_destination: false,
            })
            .unwrap();

        assert_eq!(
            mobile
                .velocity_lock()
                .unwrap()
                .as_ref()
                .expect("a readable record must be adopted")
                .daily_total(),
            5_000,
            "the recovered history must be the stored one, not an empty one"
        );
    }
    use crate::policy::{
        create_test_bundle, create_test_bundle_at, create_test_bundle_with, PolicyRules,
    };

    fn plant_policy(storage: &FaultingStorage, rules: &PolicyRules, trust_warden: bool) -> Vec<u8> {
        let bundle = create_test_bundle(rules);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&bundle).expect("serialize policy"),
        );
        if trust_warden {
            let hex_list = vec![hex::encode(bundle.warden_pubkey)];
            storage.plant(
                TRUSTED_WARDENS_KEY,
                serde_json::to_vec(&hex_list).expect("serialize wardens"),
            );
        }
        bundle.warden_pubkey.to_vec()
    }

    fn a_spend() -> TransactionContext {
        TransactionContext {
            amount_sats: 1,
            fee_sats: 1,
            destinations: vec![],
            has_unknown_destination: false,
        }
    }

    fn capped_rules() -> PolicyRules {
        PolicyRules {
            max_amount: Some(100_000),
            ..Default::default()
        }
    }

    /// The headline case, through the real load. One flipped byte in the stored
    /// record used to leave the evaluator holding no policy, which allowed
    /// everything; a policy whose own tamper evidence disarms the policy is
    /// worse than no policy, because the result reads like configuration.
    ///
    /// Deliberately asserts only that it faults. Where the flipped byte lands
    /// decides whether the record stops parsing or survives and fails the
    /// signature, and that moves with the generated key, so the arm is pinned
    /// by `a_record_whose_rules_were_edited_faults_as_unverified` and
    /// `an_unparseable_record_is_not_re_read_on_every_decision` instead. What
    /// this one is for is the broad property: any corruption refuses.
    #[test]
    fn a_tampered_policy_record_refuses_instead_of_vanishing() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);

        let mut tampered = storage.raw(POLICY_STORAGE_KEY).expect("planted");
        let at = tampered.len() / 2;
        tampered[at] ^= 0x01;
        storage.plant(POLICY_STORAGE_KEY, tampered);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let PolicyDecision::Deny { reason } = mobile.evaluate_policy(a_spend()).unwrap() else {
            panic!("a tampered policy record must refuse, not allow everything");
        };
        assert!(reason.contains("policy"), "{reason}");
        assert!(
            matches!(
                mobile.policy_status().unwrap(),
                PolicyStatus::Faulted { .. }
            ),
            "the refusal has to be explainable, so it must not report as unconfigured"
        );
        assert!(mobile.get_policy_info().is_none());
    }

    /// A verified record still works, so the refusals above cannot be a policy
    /// engine that simply says no.
    #[test]
    fn a_verified_policy_record_is_enforced() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Active { .. }
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Allow
        );
        let over = TransactionContext {
            amount_sats: 200_000,
            ..a_spend()
        };
        assert!(matches!(
            mobile.evaluate_policy(over).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// No record at all is the one state that means there are no rules.
    #[test]
    fn no_policy_record_allows() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::NotConfigured
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Allow
        );
    }

    /// An unreadable record is retried, because a Keystore decrypt fault can be
    /// transient with the record intact. Until it reads it refuses, and when it
    /// reads the real rules come back rather than the policy being discarded.
    #[test]
    fn an_unreadable_policy_record_refuses_and_then_recovers() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.fault(POLICY_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unreadable
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        storage.heal();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Active { .. }
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Allow
        );
    }

    /// A bundle can only have been stored while some warden was trusted, so a
    /// stored bundle with the wardens gone is a policy that cannot be
    /// attributed to a signer. Unattributable is not absent.
    #[test]
    fn a_stored_policy_with_the_wardens_lost_refuses() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), false);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// The lockout this refusal could otherwise cause has a way out that keeps
    /// the rules: trust the signer and the stored bundle verifies again. This is
    /// the warden-rotation path, and it is why refusing an unattributable policy
    /// does not require throwing it away.
    #[test]
    fn trusting_the_warden_brings_the_stored_policy_back_into_force() {
        let storage = Arc::new(FaultingStorage::default());
        let warden = plant_policy(&storage, &capped_rules(), false);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted { .. }
        ));

        mobile.add_trusted_warden(hex::encode(&warden)).unwrap();

        assert!(
            matches!(mobile.policy_status().unwrap(), PolicyStatus::Active { .. }),
            "trusting the signer must re-run the stored policy, not leave it faulted"
        );
        let over = TransactionContext {
            amount_sats: 200_000,
            ..a_spend()
        };
        assert!(matches!(
            mobile.evaluate_policy(over).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// Installing over a record that cannot be checked against would hand a
    /// rollback to anyone able to corrupt storage: the downgrade check compares
    /// against the policy in force, and a faulted record has none, so an older
    /// bundle carrying a real warden signature would install cleanly.
    #[test]
    fn a_policy_cannot_be_installed_over_one_that_will_not_verify() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.fault(POLICY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let replacement = create_test_bundle(&PolicyRules::default());
        let hex_bundle = hex::encode(replacement.to_bytes());
        let err = mobile
            .import_policy(hex_bundle)
            .expect_err("installing over an unverifiable record must be refused");
        // `InvalidPolicy`'s Display drops `msg`, so the reason is only in the
        // field a caller destructures.
        let KeepMobileError::InvalidPolicy { msg } = err else {
            panic!("expected the install to be refused for the fault, got {err:?}");
        };
        assert!(msg.contains("Delete the stored policy first"), "{msg}");

        mobile.delete_policy().unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::NotConfigured
        ));
    }
    /// An unreadable wardens record leaves a stored bundle unattributable on a
    /// fresh evaluator, which is a refusal and not an absence.
    #[test]
    fn an_unreadable_wardens_record_refuses_a_stored_policy() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.fault(TRUSTED_WARDENS_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// The warden set in memory survives a wardens record that cannot be read
    /// back. Without that, adding a warden would persist it and then lose it on
    /// the very reload meant to put the policy back in force, so the rotation
    /// recovery would fail exactly when storage is already misbehaving.
    #[test]
    fn adding_a_warden_survives_a_wardens_record_that_cannot_be_read_back() {
        let storage = Arc::new(FaultingStorage::default());
        let warden = plant_policy(&storage, &capped_rules(), false);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted { .. }
        ));

        storage.fault(TRUSTED_WARDENS_KEY);
        mobile.add_trusted_warden(hex::encode(&warden)).unwrap();

        assert!(
            matches!(mobile.policy_status().unwrap(), PolicyStatus::Active { .. }),
            "the warden just added must not be dropped by the reload that follows it"
        );
        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(&warden)]
        );
    }
    /// Deterministic, unlike flipping a byte at the record's midpoint: a byte
    /// inside `rules_json` always survives parsing and always breaks the hash,
    /// so this pins the arm and not merely that something faulted.
    #[test]
    fn a_record_whose_rules_were_edited_faults_as_unverified() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);

        let raw = storage.raw(POLICY_STORAGE_KEY).expect("planted");
        let text = String::from_utf8(raw).expect("json");
        let edited = text.replace("100000", "900000");
        assert_ne!(edited, text, "the fixture must contain the cap to edit");
        storage.plant(POLICY_STORAGE_KEY, edited.into_bytes());

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        let over = TransactionContext {
            amount_sats: 500_000,
            ..a_spend()
        };
        assert!(
            matches!(
                mobile.evaluate_policy(over).unwrap(),
                PolicyDecision::Deny { .. }
            ),
            "the raised cap must not take effect, and the record must not read as no policy"
        );
    }

    /// A record that will not parse will not parse next time either, so it must
    /// not be the retryable arm. Classified as unreadable it would put two
    /// Keystore decrypts on every decision for the life of the process, for a
    /// condition that cannot resolve.
    #[test]
    fn an_unparseable_record_is_not_re_read_on_every_decision() {
        let storage = Arc::new(FaultingStorage::default());
        storage.plant(POLICY_STORAGE_KEY, b"not json at all".to_vec());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        let after_load = storage.reads_of(POLICY_STORAGE_KEY);
        for _ in 0..5 {
            assert!(matches!(
                mobile.evaluate_policy(a_spend()).unwrap(),
                PolicyDecision::Deny { .. }
            ));
        }
        assert_eq!(
            storage.reads_of(POLICY_STORAGE_KEY),
            after_load,
            "a permanent fault must not be re-read per decision"
        );
    }

    /// A device that boots before its clock syncs dates a good policy in the
    /// future. That resolves by itself within seconds, so it refuses meanwhile
    /// and keeps looking, rather than holding the refusal for the whole process
    /// and offering only deletion as the way out.
    #[test]
    fn a_policy_dated_ahead_of_the_clock_refuses_and_keeps_retrying() {
        let storage = Arc::new(FaultingStorage::default());
        let ahead = chrono::Utc::now().timestamp() as u64 + 7 * 24 * 60 * 60;
        let bundle = create_test_bundle_at(&capped_rules(), ahead);
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&bundle).unwrap());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)]).unwrap(),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::NotYetValid
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend()).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        let after_load = storage.reads_of(POLICY_STORAGE_KEY);
        mobile.evaluate_policy(a_spend()).unwrap();
        assert!(
            storage.reads_of(POLICY_STORAGE_KEY) > after_load,
            "a fault that resolves on its own has to be looked at again"
        );
    }

    /// Renewal must not require destroying the policy first. By the time the
    /// clock check fails the signature and signer already held, so the expired
    /// bundle is still a sound baseline to measure the replacement against.
    #[test]
    fn a_replacement_installs_over_an_expired_policy_without_deleting_it() {
        let storage = Arc::new(FaultingStorage::default());
        let long_ago = chrono::Utc::now().timestamp() as u64 - 400 * 24 * 60 * 60;
        let old = create_test_bundle_at(&capped_rules(), long_ago);
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&old).unwrap());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(old.warden_pubkey)]).unwrap(),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Expired
            }
        ));
        assert!(
            matches!(
                mobile.evaluate_policy(a_spend()).unwrap(),
                PolicyDecision::Deny { .. }
            ),
            "stale rules are neither enforced nor ignored"
        );

        let fresh = create_test_bundle(&capped_rules());
        mobile
            .add_trusted_warden(hex::encode(fresh.warden_pubkey))
            .unwrap();
        mobile
            .import_policy(hex::encode(fresh.to_bytes()))
            .expect("a replacement must install over an expired policy");

        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// The escape hatch must not report success on a delete that did not
    /// happen: memory would open the gate for this process while the record
    /// stayed put and faulted again at the next launch.
    #[test]
    fn a_delete_that_fails_leaves_the_policy_refusing() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.fault(POLICY_STORAGE_KEY);
        storage.fault_delete(POLICY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(mobile.delete_policy().is_err());
        assert!(
            matches!(
                mobile.policy_status().unwrap(),
                PolicyStatus::Faulted { .. }
            ),
            "a failed delete must not leave memory reading as no policy"
        );
    }

    /// A transient fault must not push the caller into discarding a
    /// warden-signed policy, so an install reads the record again first.
    ///
    /// Both bundles come from one warden on purpose. Trusting a new warden
    /// re-runs the load itself, which would mask whether the install does, so
    /// this leaves the install as the only thing that can clear the fault.
    #[test]
    fn an_install_retries_a_fault_that_has_already_healed() {
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let now = chrono::Utc::now().timestamp() as u64;
        let stored = create_test_bundle_with(&warden, &capped_rules(), now - 60);

        let storage = Arc::new(FaultingStorage::default());
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&stored).unwrap());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(stored.warden_pubkey)]).unwrap(),
        );
        storage.fault(POLICY_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unreadable
            }
        ));

        storage.heal();
        let replacement = create_test_bundle_with(&warden, &capped_rules(), now);
        mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .expect("a healed fault must not force a delete");
        assert!(matches!(
            mobile.policy_status().unwrap(),
            PolicyStatus::Active { .. }
        ));
    }
}
