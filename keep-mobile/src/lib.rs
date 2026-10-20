// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod approver;
mod audit;
mod clock_floor;
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
mod warden_auth;

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
    SigningRiskAssessment, SigningRiskFactor, StorageRead, UsageStats,
};
pub use storage::{PendingShareInfo, SecureStorage, ShareInfo, ShareMetadataInfo, StoredShareInfo};
pub use types::{
    AnnouncedXpubInfo, BackupInfo, ConnectionStatus, DescriptorProposal, DeviceRegistrationInfo,
    DkgConfig, DkgParticipant, DkgProgressUpdate, FrostGenerationResult, GeneratedShareInfo,
    KeepLiveState, KeyHealthStatusInfo, PeerInfo, PeerStatus, RecoveryTierConfig,
    RosterVerification, SignRequest, SignRequestMetadata, ThresholdConfig, WalletDescriptorInfo,
};
pub use warden_auth::WardenGovernance;

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
use policy::{PolicyBundle, PolicyEvaluator, POLICY_PUBKEY_LEN};
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
const CLOCK_FLOOR_STORAGE_KEY: &str = "__keep_clock_floor_v1";

/// The fault a time-floor error stands for. A corrupt record will not clear, so
/// it is the fault that is not retried and that says deleting the policy is the
/// way out; reporting it as unreadable would tell the caller to wait. A failed
/// read may clear, so it stays the retried one.
///
/// Sound only because `floor_now` produces `InvalidPolicy` for a corrupt record
/// and nothing else: storage errors are passed through `floor_storage_error`
/// on the way out, so a storage implementation returning that variant cannot be
/// read as corruption and turn a transient fault into one that is never retried.
fn floor_fault(e: &KeepMobileError) -> PolicyFault {
    match e {
        KeepMobileError::InvalidPolicy { .. } => PolicyFault::ClockUntrusted,
        _ => PolicyFault::Unreadable,
    }
}

/// A storage error reaching the time floor, with `InvalidPolicy` taken out of
/// it. That variant is how `floor_now` says a record is corrupt, and the storage
/// error type admits any variant, so one coming from storage is restated as the
/// read failure it is.
fn floor_storage_error(e: KeepMobileError) -> KeepMobileError {
    match e {
        KeepMobileError::InvalidPolicy { .. } => KeepMobileError::StorageError {
            msg: "The time floor could not be read or written".into(),
        },
        other => other,
    }
}

/// Serializes the time floor's read-modify-write across the whole process.
///
/// Process-wide rather than per instance because the record is: two instances
/// on the same storage would each hold their own lock and still race the load
/// and the store, and the later store would erase the other's advance. Taken
/// before any policy lock and never while one is held. It cannot cover another
/// process, which would need a lock in the storage itself.
static FLOOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every authorized change to the warden set and the policy across
/// the process, so two instances on the same storage cannot both read one
/// epoch and both spend it. Taken before the floor lock and the policy lock.
static GOVERNANCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
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
    /// Advanced each time the live node is torn down, after it is gone. A
    /// running bunker holds its own copy of the share, or a handle to the old
    /// node, and the relay pins it started with, so it stops when this moves
    /// rather than signing on with a share that was deleted or switched away
    /// from, or trusting a pin that was removed.
    pub(crate) live_generation: tokio::sync::watch::Sender<u64>,
    /// Serializes every bunker start against revokes and credential
    /// rotations, whichever `BunkerHandler` each is made through: a start reads
    /// the persisted grants before it publishes its engine, and a revoke in
    /// between would be lost.
    pub(crate) bunker_start_lock: std::sync::Mutex<()>,
    /// The engine of the bunker last started, through any `BunkerHandler`, so
    /// a revoke reaches it whichever instance the revoke is made through. Weak,
    /// so it dies with the server.
    pub(crate) live_bunker: std::sync::Mutex<Option<std::sync::Weak<keep_nip46::SignerHandler>>>,
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
        // Before the policy loads, so one whose wardens record was lost comes
        // back into force under its signer rather than refusing every spend.
        {
            let _governance = GOVERNANCE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(e) = Self::stored_or_restored_wardens(&storage) {
                tracing::error!("Trusted wardens unreadable at startup: {e}");
            }
        }
        // The floor is consulted and not advanced here: no monotonic reading is
        // available at construction, and advancing needs one. A floor that
        // cannot be read faults the policy instead of failing construction,
        // because refusing to open the app is not better than refusing every
        // spend, and the fault is retried before each decision.
        match Self::startup_policy_now(&storage) {
            Ok(clock) => Self::load_policy_into(&storage, &mut evaluator, clock),
            Err(e) if matches!(e, KeepMobileError::InvalidPolicy { .. }) => {
                if let Ok(wardens) = persistence::load_trusted_wardens(&storage) {
                    evaluator.set_trusted_wardens(wardens);
                }
                tracing::error!(
                    "Time floor corrupt, every policy rule will refuse until the policy is deleted"
                );
                evaluator.set_policy_faulted(floor_fault(&e), None);
            }
            // Faulted only when there is a policy for the floor to protect. A
            // device with no policy record has nothing to wind the clock back
            // into, so it starts with no policy, and the floor is retried on
            // the next decision. A corrupt floor never reaches here on such a
            // device, because it is replaced instead; what does is a read that
            // did not complete.
            Err(_) => {
                // The wardens are loaded either way, because the floor is no
                // reason to lose them. With the policy left out of memory,
                // nothing re-reads them: on a device with no policy nothing is
                // faulted, and on one with a policy the retry needs the floor
                // first. Skipping them left the set empty for the life of the
                // process while the record held wardens, so deleting the policy
                // to recover from a corrupt floor ended with no trusted signer
                // and the replacement refused.
                if let Ok(wardens) = persistence::load_trusted_wardens(&storage) {
                    evaluator.set_trusted_wardens(wardens);
                }
                match persistence::load_policy(&storage) {
                    Err(KeepMobileError::StorageNotFound) => evaluator.clear_policy(),
                    _ => {
                        tracing::error!(
                            "Time floor unreadable, every policy rule will refuse until it is read"
                        );
                        evaluator.set_policy_faulted(PolicyFault::Unreadable, None);
                    }
                }
            }
        }

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
            live_generation: tokio::sync::watch::Sender::new(0),
            bunker_start_lock: std::sync::Mutex::new(()),
            live_bunker: std::sync::Mutex::new(None),
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
        let result = self.storage.delete_share();
        self.invalidate_live_node();
        result
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
        // After the node is gone, so a bunker start that read the old node
        // subscribed before this and sees it.
        self.live_generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
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
        let is_active = match self.storage.read_active_share_key() {
            signing_policy::StorageRead::Found { value } => {
                constant_time_eq(value.as_bytes(), group_pubkey.as_bytes())
            }
            signing_policy::StorageRead::Absent => false,
            // Whether this is the active share decides whether the pointer is
            // cleared with it, so a pointer that cannot be read refuses the
            // delete rather than leave it naming a share that is gone.
            signing_policy::StorageRead::Unavailable => {
                return Err(KeepMobileError::StorageError {
                    msg: "The active share could not be read; try the delete again".into(),
                })
            }
        };

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
        let proxy = self.configured_proxy()?;

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
        // Held for the whole install, so a revocation or a warden change cannot
        // land between the stored record being checked and this one replacing
        // it.
        let _governance = GOVERNANCE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Judged against the floor, not the raw clock, so a bundle that is
        // already expired cannot be installed by winding the date back to
        // inside its window.
        let clock = self.policy_now(None)?;
        bundle.verify_timestamp_at(clock)?;

        // A transient fault must not push the caller into discarding a
        // warden-signed policy, so the record gets another read first.
        self.reload_policy_if_transient(clock)?;

        let mut policy = self.policy_write_lock()?;
        // Refused when the stored record cannot say how old it is, rather than
        // installed over it. The rollback check below needs a baseline, and a
        // record that failed verification is not one: accepting the install
        // would let anyone who can corrupt the record roll the policy back to
        // an older bundle that still carries a real warden signature. An
        // expired bundle is attributed, so it is still a baseline and a
        // replacement installs over it normally.
        //
        // Worth being exact about what this buys, because it is less than it
        // looks. The baseline is read out of the same record it is protecting,
        // so an attacker who can roll the stored bytes back to an older
        // warden-signed bundle gets no comparison at all: that bundle loads as
        // `Active` on its own terms and this check never runs. It also takes no
        // FFI call, so authenticating `delete_policy` would not close it.
        // Closing it needs a high-water mark kept outside the record and
        // refused below, which is follow-up work.
        if policy.fault().is_some() && policy.rollback_baseline().is_none() {
            return Err(KeepMobileError::InvalidPolicy {
                msg: "Refusing to replace a policy that cannot be checked against. \
                      A trusted warden has to revoke the stored policy first."
                    .into(),
            });
        }
        // Judged against the stored set rather than memory, which another
        // instance on the same storage may have changed since this one loaded.
        let (set, device) = Self::governance_set(&self.storage)?;
        bundle.verify_trusted_warden(&set.wardens)?;
        bundle.verify_version_upgrade(policy.rollback_baseline())?;

        let info = bundle.to_policy_info();
        // The record goes first, for the same reason it does in
        // `delete_policy`. Committing to memory first means a failed write
        // returns an error while this process goes on enforcing the bundle it
        // just refused to store: a renewal that relaxes a limit takes effect
        // unstored, and a `Faulted` deny-all is lifted until the next launch,
        // where `reload_policy_if_transient` cannot undo it because the fault
        // is already gone from memory.
        //
        // The epoch advances before that, as it does for a revocation, so an
        // authorization the warden sent and no longer wants used, such as a
        // revocation held back while a read was failing, is spent by the
        // install rather than left to remove the policy that replaced it. If
        // the install then fails, it was spent for nothing, which is safe.
        persistence::persist_warden_set(
            &self.storage,
            &persistence::WardenSet {
                epoch: Self::next_epoch(set.epoch)?,
                wardens: set.wardens,
                device: Some(device),
                // A bundle can be installed from one signed before the
                // restore, so it is not the warden acting on it.
                restored: set.restored,
            },
        )?;
        persistence::persist_policy(&self.storage, &bundle)?;
        policy.set_policy(bundle.clone());

        Ok(info)
    }

    /// The policy in force, which is `None` both when none is configured and
    /// when the stored one cannot be trusted. Use [`Self::policy_status`] to
    /// tell those apart; they behave as opposites.
    ///
    /// Takes the clock so "in force" means what it says: a bundle whose window
    /// closed is not in force, even while this process still holds it, and
    /// reporting its limits would describe rules nothing will honor.
    pub fn get_policy_info(&self, now_elapsed_ms: Option<u64>) -> Option<PolicyInfo> {
        let clock = self.policy_now(now_elapsed_ms).ok()?;
        // Healed first, as `policy_status` does, so the two cannot answer
        // differently on the same tick: without it a transient fault that
        // status would have cleared into `Active` still reads as no policy here.
        self.reload_policy_if_transient(clock).ok()?;
        self.policy_read_lock()
            .ok()?
            .policy_at(clock)
            .map(|b| b.to_policy_info())
    }

    /// How a floor that cannot be read answers, which depends on whether there
    /// is a policy for it to protect.
    ///
    /// With one, the floor is the only thing saying the clock was not wound
    /// back, so its absence refuses. With none, there is nothing to wind back
    /// into: the device would otherwise be left refusing permanently over a
    /// record that guards nothing, and nothing deletes it.
    fn policy_configured(&self) -> Result<bool, KeepMobileError> {
        Ok(self.policy_read_lock()?.is_configured())
    }

    fn floor_fault_status(&self, e: KeepMobileError) -> Result<PolicyStatus, KeepMobileError> {
        if self.policy_configured()? {
            let fault = floor_fault(&e);
            tracing::error!("Time floor unusable ({fault}), the stored policy will refuse");
            return Ok(PolicyStatus::Faulted { fault });
        }
        Ok(PolicyStatus::NotConfigured)
    }

    fn floor_fault_decision(&self, e: KeepMobileError) -> Result<PolicyDecision, KeepMobileError> {
        if self.policy_configured()? {
            let fault = floor_fault(&e);
            tracing::error!("Time floor unusable ({fault}), refusing the spend");
            return Ok(PolicyDecision::Deny {
                reason: format!("Cannot evaluate the spending policy: {fault}"),
            });
        }
        Ok(PolicyDecision::Allow)
    }

    /// Whether a policy is configured, in force, or stored and untrustworthy.
    ///
    /// A faulted record refuses every spend, so reporting it as no policy would
    /// leave a caller unable to explain the refusals. Retries an unreadable
    /// record first, so a transient read fault is not reported as a fault.
    /// `now_elapsed_ms` is the platform's monotonic clock, as
    /// `SigningRateLimiter::check_and_record` already takes: on Android,
    /// `SystemClock.elapsedRealtime()`. It is what lets the stored time floor
    /// advance. Pass `None` when there is no such reading, never a stand-in:
    /// `None` holds the floor where it is, which is safe, whereas an invented
    /// small value re-anchors it and the next real reading credits the whole
    /// device uptime. Zero is read as `None` for that reason.
    pub fn policy_status(
        &self,
        now_elapsed_ms: Option<u64>,
    ) -> Result<PolicyStatus, KeepMobileError> {
        // The floor is advanced here, before anything can return early. It is
        // what makes winding the clock back detectable, and a floor that only
        // moved while the policy happened to be faulted would never move on a
        // working install, which is the case the attack is run against.
        let clock = match self.policy_now(now_elapsed_ms) {
            Ok(clock) => clock,
            // Reported as a fault rather than an error: a caller rendering
            // status must be able to say the policy cannot be trusted, and
            // without the floor nothing says the clock was not wound back.
            //
            // Only when there is a policy to protect. With none configured the
            // floor guards nothing, and refusing on it would turn an
            // unreadable record into a permanent refusal on a device that never
            // had a policy: nothing deletes this record, so it would outlive
            // every restart with no policy to delete.
            Err(e) => return self.floor_fault_status(e),
        };
        self.reload_policy_if_transient(clock)?;
        Ok(self.policy_read_lock()?.status(clock))
    }

    /// Removes the stored policy, on the authority of a trusted warden.
    ///
    /// The policy is a constraint a warden places on the device, so removing
    /// it takes `revocation`, a [`warden_auth::WardenAuthorization`] signed by a
    /// warden the device trusts, naming this policy and the device's current
    /// warden epoch. Without one, anyone holding the device could remove the
    /// policy and spend without limit.
    ///
    /// The revocation names the stored policy by its digest when that policy
    /// verifies as a trusted warden's, or otherwise by the fixed subject for a
    /// policy that cannot be attributed: one that will not decrypt, will not
    /// parse, or parses and fails its signature, hash or signer check. With no
    /// policy stored there is nothing to remove and
    /// no revocation is needed; the time floor is still reset, see below.
    ///
    /// If no trusted warden can sign one, because the warden keys were lost,
    /// the policy cannot be removed and wiping the app data is the way out.
    /// That is deliberate: a constraint that can be lifted without its warden
    /// is not a constraint.
    pub fn delete_policy(&self, revocation: Option<String>) -> Result<(), KeepMobileError> {
        // Governance, then floor, then policy: the one order every path takes.
        let _governance = GOVERNANCE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _floor = FLOOR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut policy = self.policy_write_lock()?;

        // What is stored decides what the revocation has to name. Read fresh,
        // because memory can hold a faulted state with no bundle in it.
        let stored = match persistence::load_policy(&self.storage) {
            Ok(bundle) => Some(Some(bundle)),
            Err(KeepMobileError::StorageNotFound) => None,
            Err(_) => Some(None),
        };

        if let Some(stored) = stored {
            let (set, device) = Self::governance_set(&self.storage)?;
            // A policy is named by its digest only when it verifies as what a
            // trusted warden signed, because only then does the warden know it.
            // Anything else stored, whether it will not decrypt, will not parse,
            // or parses with edited rules or under a signer no longer trusted,
            // faults with no baseline, so an install is refused over it, and the
            // digest of whatever bytes are there is known to nobody. Requiring
            // that digest left those devices refusing every spend until they
            // were wiped, so they are all named by the one fixed subject.
            //
            // That subject still needs a trusted warden's signature for this
            // device at its current epoch, and the epoch advances on every
            // install and every change, so it cannot be carried to another
            // device or used on a policy installed after it was signed.
            let subject = match stored {
                Some(bundle)
                    if bundle.verify_signature().is_ok()
                        && bundle.verify_hash().is_ok()
                        && bundle.verify_trusted_warden(&set.wardens).is_ok() =>
                {
                    bundle.digest()
                }
                _ => warden_auth::unreadable_policy_subject(),
            };
            let revocation = revocation.ok_or_else(|| KeepMobileError::InvalidPolicy {
                msg: "Removing the policy needs a revocation signed by a trusted warden".into(),
            })?;
            warden_auth::WardenAuthorization::from_hex(&revocation)?.authorize(
                warden_auth::WardenAction::RevokePolicy,
                &subject,
                &device,
                set.epoch,
                &set.wardens,
            )?;

            // Consumed before it is acted on. If the deletion below fails, the
            // revocation is spent and a new one is needed, which is the safe
            // way round: acting first and failing to advance the epoch would
            // leave a revocation that could be used again.
            persistence::persist_warden_set(
                &self.storage,
                &persistence::WardenSet {
                    wardens: set.wardens,
                    epoch: Self::next_epoch(set.epoch)?,
                    device: Some(device),
                    restored: false,
                },
            )?;

            // The record goes first and the error is surfaced. Clearing memory
            // on a delete that did not happen reports success, opens the gate
            // for this process, and faults again at the next launch.
            match self.storage.delete_share_by_key(POLICY_STORAGE_KEY.into()) {
                Ok(()) | Err(KeepMobileError::StorageNotFound) => {}
                Err(e) => return Err(e),
            }
        }
        // Also when nothing was stored: memory then holds a policy storage no
        // longer has, such as one another instance revoked, and reporting
        // success while still enforcing it would be false.
        policy.clear_policy();

        // The time floor goes with it, and needs no revocation when no policy
        // is stored because then it guards nothing. A floor is seeded from the
        // wall clock when first written, before any monotonic reading can bound
        // it, so a device whose clock was far ahead at that moment holds a floor
        // in the future that nothing lowers: every bundle reads as expired, and
        // no first policy could be installed until real time caught up.
        match self
            .storage
            .delete_share_by_key(CLOCK_FLOOR_STORAGE_KEY.into())
        {
            Ok(()) | Err(KeepMobileError::StorageNotFound) => {}
            Err(_) => tracing::warn!(
                "The time floor could not be reset; call delete_policy again, which needs no \
                 revocation once no policy is stored"
            ),
        }
        Ok(())
    }

    /// `now_elapsed_ms` is the platform's monotonic clock; see
    /// [`Self::policy_status`].
    pub fn evaluate_policy(
        &self,
        ctx: TransactionContext,
        now_elapsed_ms: Option<u64>,
    ) -> Result<PolicyDecision, KeepMobileError> {
        self.reload_velocity_if_unknown()?;
        // As in `policy_status`: advanced before any early return, so the floor
        // tracks on an install where nothing is faulted.
        let clock = match self.policy_now(now_elapsed_ms) {
            Ok(clock) => clock,
            // A refusal, not an error. The contract on `evaluate` says an error
            // is not a decision, so a floor that cannot be read would leave the
            // guarantee resting on the foreign caller honoring that; answering
            // `Deny` here keeps it on this side of the boundary. Only when
            // there is a policy to protect, for the reason given on
            // `floor_fault_status`.
            Err(e) => return self.floor_fault_decision(e),
        };
        self.reload_policy_if_transient(clock)?;
        self.policy_read_lock()?.evaluate(&ctx, clock)
    }

    /// Counts a spend against the velocity limits.
    ///
    /// Call this before the spend completes, and do not complete it when this
    /// returns an error. A spend that happened without being counted is one the
    /// daily and weekly limits will not see again, so the limits under-count
    /// from then on; refusing the spend is the only thing that keeps the
    /// counters and reality in agreement. There is no caller yet, so the
    /// contract is stated here before one exists rather than inferred later.
    ///
    /// The count lands in memory first and is persisted second, which is
    /// deliberate and the opposite of what the policy record does. A failed
    /// write leaves this process counting a spend that storage does not hold,
    /// which enforces too strictly rather than too loosely; committing to
    /// storage first would leave a failed write counting nothing anywhere, so
    /// the live process would under-count immediately instead of only after a
    /// restart. Neither ordering makes an uncounted spend safe, which is why
    /// the caller has to refuse it.
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

    /// Trusts another warden, on the authority of one already trusted.
    ///
    /// `authorization` is a [`warden_auth::WardenAuthorization`] for adding
    /// this key, signed by a trusted warden at the current warden epoch. It is
    /// required because whoever could add a warden could add their own and
    /// then sign any revocation or replacement policy they liked.
    ///
    /// The one exception is the first warden on a device that has never had
    /// one and holds no policy: there is no one yet to authorize it, and such a
    /// device has nothing to protect. A device that holds a policy and has no
    /// warden left in its set accepts no new one; wiping the app data is the
    /// way out. One whose wardens record was lost outright gets the stored
    /// policy's signer back instead.
    ///
    /// Trusting a warden re-runs the stored policy against the new set, which
    /// is how a policy faulted for an untrusted signer comes back into force
    /// after a key rotation without its rules being discarded.
    pub fn add_trusted_warden(
        &self,
        pubkey_hex: String,
        authorization: Option<String>,
    ) -> Result<(), KeepMobileError> {
        let pubkey = network::parse_warden_pubkey(&pubkey_hex)?;
        self.mutate_trusted_wardens(pubkey, true, authorization)
    }

    /// Stops trusting a warden, on the authority of one trusted, which may be
    /// the warden being removed.
    ///
    /// The signer of the stored policy cannot be removed while that policy is
    /// stored; a rotation installs a replacement signed by another warden
    /// first, or revokes the policy.
    pub fn remove_trusted_warden(
        &self,
        pubkey_hex: String,
        authorization: String,
    ) -> Result<(), KeepMobileError> {
        // Length only, not the curve check, so a key stored before keys were
        // checked can still be removed.
        let pubkey = network::parse_warden_pubkey_bytes(&pubkey_hex)?;
        self.mutate_trusted_wardens(pubkey, false, Some(authorization))
    }

    /// The device id and warden epoch an authorization has to name. A warden
    /// reads them to sign the next change; the epoch advances with every change
    /// authorized and every policy installed.
    pub fn warden_governance(&self) -> Result<WardenGovernance, KeepMobileError> {
        let _governance = GOVERNANCE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (set, device) = Self::governance_set(&self.storage)?;
        Ok(WardenGovernance {
            device_id: hex::encode(device),
            epoch: set.epoch,
            restored: set.restored,
        })
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

    /// Repairs the descriptor index, which every descriptor save and delete
    /// refuses while it cannot be read. Each group this device holds a share
    /// of whose descriptor record is stored is added, and nothing is removed,
    /// so running it again once more shares read back recovers what an earlier
    /// run missed. Refused when no shares are listed. Returns how many
    /// descriptors the index lists afterwards.
    ///
    /// An index that cannot be read or parsed is replaced only with
    /// `replace_unreadable`, since the share list can under-report and a
    /// failed read may succeed later; otherwise its error is returned, which
    /// for one that will not parse starts with "Descriptor index is
    /// unreadable". Replacing leaves the
    /// descriptors it listed for groups not held here stored but unlisted
    /// until saved again, so the app passes `replace_unreadable` only after
    /// the user confirms, having retried first.
    pub fn wallet_descriptor_repair_index(
        &self,
        replace_unreadable: bool,
    ) -> Result<u32, KeepMobileError> {
        let _guard =
            self.descriptor_write_lock
                .lock()
                .map_err(|_| KeepMobileError::StorageError {
                    msg: "descriptor lock poisoned".into(),
                })?;
        let held = self
            .storage
            .list_all_shares()
            .into_iter()
            .map(|meta| hex::encode(meta.group_pubkey));
        let index = persistence::repair_descriptor_index(&self.storage, held, replace_unreadable)?;
        Ok(u32::try_from(index.len()).unwrap_or(u32::MAX))
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
        let proxy = self.configured_proxy()?;
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
            bunker_permissions_scope: existing.bunker_permissions_scope,
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
        // The same holds for an index that cannot be read, which no save or
        // delete gets past until `wallet_descriptor_repair_index` runs: the
        // descriptors of the groups held here are read without it, and any
        // other group's is left out.
        let load = match persistence::load_descriptors(&self.storage) {
            Ok(load) => load,
            Err(e) => {
                tracing::warn!(
                    "Descriptor index unreadable, backing up the descriptors of held groups only: {e}"
                );
                let held: std::collections::BTreeSet<String> = all_share_meta
                    .iter()
                    .map(|meta| hex::encode(&meta.group_pubkey))
                    .collect();
                persistence::load_listed_descriptors(&self.storage, held)
            }
        };
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
                bunker_permissions_scope: None,
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

        // Only a pointer known to be unset is set: one that could not be read
        // may name another account, and repointing it here would skip the
        // cleanup an account switch needs.
        match self.storage.read_active_share_key() {
            signing_policy::StorageRead::Absent => {
                if let Some(group_hex) = first_group_hex {
                    let _ = self.storage.set_active_share_key(Some(group_hex));
                }
            }
            signing_policy::StorageRead::Found { .. } => {}
            signing_policy::StorageRead::Unavailable => {
                tracing::warn!("active share unreadable; restore leaves it as it is");
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
    /// The one implementation of both warden mutations, because the ordering is
    /// what is being protected and it was written out twice.
    ///
    /// The record goes before memory: a set committed to memory that storage
    /// never accepted would trust a signer across this process and not the
    /// next, and on the insert side that is a bundle attributed to a warden the
    /// device has no record of trusting. The reload comes last, so the stored
    /// policy is re-attributed against the set that actually persisted.
    fn mutate_trusted_wardens(
        &self,
        pubkey: [u8; POLICY_PUBKEY_LEN],
        trust: bool,
        authorization: Option<String>,
    ) -> Result<(), KeepMobileError> {
        let _governance = GOVERNANCE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let clock = self.policy_now(None)?;
        let mut policy = self.policy_write_lock()?;

        // Read from storage under the lock, because the epoch checked has to be
        // the one written, and memory does not hold it.
        let (set, device) = Self::governance_set(&self.storage)?;

        let first_warden = trust
            && set.wardens.is_empty()
            && matches!(
                persistence::load_policy(&self.storage),
                Err(KeepMobileError::StorageNotFound)
            );
        if !first_warden {
            if set.wardens.is_empty() {
                return Err(KeepMobileError::InvalidPolicy {
                    msg: "A policy is stored and no trusted warden remains to authorize this; \
                          wipe the app data to recover"
                        .into(),
                });
            }
            let authorization = authorization.ok_or_else(|| KeepMobileError::InvalidPolicy {
                msg: "Changing the trusted wardens needs an authorization from a trusted warden"
                    .into(),
            })?;
            let action = if trust {
                warden_auth::WardenAction::AddWarden
            } else {
                warden_auth::WardenAction::RemoveWarden
            };
            warden_auth::WardenAuthorization::from_hex(&authorization)?.authorize(
                action,
                &pubkey,
                &device,
                set.epoch,
                &set.wardens,
            )?;
        }

        // Checked after the authorization, so a change that would not happen
        // still never accepts one that does not verify.
        if set.wardens.contains(&pubkey) == trust {
            return Ok(());
        }

        let mut wardens = set.wardens;
        if trust {
            wardens.insert(pubkey);
        } else {
            wardens.remove(&pubkey);
            let stored = match persistence::load_policy(&self.storage) {
                Ok(bundle) => Some(Some(bundle)),
                Err(KeepMobileError::StorageNotFound) => None,
                Err(KeepMobileError::InvalidPolicy { .. }) => Some(None),
                Err(e) => return Err(e),
            };
            // The signer of the stored policy stays while it is stored, which
            // is what lets a lost wardens record be rebuilt from that signer
            // without trusting a warden that was taken out. A rotation away
            // from a compromised key installs a replacement signed by another
            // warden first. A record that cannot be read now may verify later,
            // so it refuses above; one that will never parse names no signer.
            if let Some(Some(bundle)) = &stored {
                if bundle.warden_pubkey == pubkey
                    && bundle.verify_signature().is_ok()
                    && bundle.verify_hash().is_ok()
                {
                    return Err(KeepMobileError::InvalidPolicy {
                        msg: "The stored policy's signer stays trusted while that policy is \
                              stored; install a replacement signed by another warden, or \
                              revoke the policy first"
                            .into(),
                    });
                }
            }
            // Emptying the set under a stored policy leaves nothing able to
            // revoke it, so the only way out is a wipe that loses the share.
            // A rotation adds the new key first and never gets here; the way
            // to disengage entirely is to revoke the policy first. Only keys
            // that can sign count, since one stored before keys were checked
            // as curve points keeps the set non-empty and revokes nothing.
            if stored.is_some()
                && !wardens
                    .iter()
                    .any(|key| k256::schnorr::VerifyingKey::from_bytes(key).is_ok())
            {
                return Err(KeepMobileError::InvalidPolicy {
                    msg: "Removing the last trusted warden would leave the stored policy with \
                          nothing able to revoke it; revoke the policy first"
                        .into(),
                });
            }
        }
        // The set and the advanced epoch land in one write, so the
        // authorization is spent exactly when the change takes effect.
        let next = persistence::WardenSet {
            wardens,
            epoch: Self::next_epoch(set.epoch)?,
            device: Some(device),
            restored: false,
        };
        persistence::persist_warden_set(&self.storage, &next)?;
        policy.set_trusted_wardens(next.wardens);
        Self::load_policy_into(&self.storage, &mut policy, clock);
        Ok(())
    }

    /// The stored warden set, or an empty one at epoch 0 when none was ever
    /// written, with its device id generated and stored first if it has none.
    /// A set that cannot be read is an error: without its epoch there is
    /// nothing to stop an authorization being replayed. Called only under
    /// `GOVERNANCE_LOCK`, so two callers cannot each generate a different id.
    ///
    /// A record from before the id existed gets one here, and an authorization
    /// signed before that cannot name it, so it is refused; the warden reads
    /// the id with [`Self::warden_governance`] and signs again.
    fn governance_set(
        storage: &Arc<dyn SecureStorage>,
    ) -> Result<(persistence::WardenSet, [u8; 32]), KeepMobileError> {
        let mut set =
            Self::stored_or_restored_wardens(storage)?.unwrap_or(persistence::WardenSet {
                wardens: std::collections::HashSet::new(),
                epoch: 0,
                device: None,
                restored: false,
            });
        let device = match set.device {
            Some(device) => device,
            None => {
                let device = keep_core::crypto::try_random_bytes::<32>()?;
                set.device = Some(device);
                persistence::persist_warden_set(storage, &set)?;
                device
            }
        };
        Ok((set, device))
    }

    /// The stored warden set, or `None` on a device that has never had one.
    ///
    /// A wardens record absent beside a stored policy was lost, not never
    /// written, since a policy only installs against a trusted warden. Storage
    /// that keeps each record in its own file can roll one back to nothing on a
    /// power loss while the policy survives. Writing an empty set there would
    /// leave the policy with nothing able to revoke it, and refusing would
    /// leave a wipe that loses the share as the only way out, so the set is
    /// rebuilt from the signer of the policy in force. That warden already
    /// governs the device through that policy; any others, and any removal of
    /// it, have to be made again. The rebuilt set gets a new device id, so no
    /// authorization signed before the loss applies at its epoch 0.
    ///
    /// A policy that does not verify names no signer to rebuild from, so that
    /// is refused and the device is recovered by wiping. Called only under
    /// `GOVERNANCE_LOCK`, for the same reason as [`Self::governance_set`].
    fn stored_or_restored_wardens(
        storage: &Arc<dyn SecureStorage>,
    ) -> Result<Option<persistence::WardenSet>, KeepMobileError> {
        match persistence::load_warden_set(storage) {
            Err(KeepMobileError::StorageNotFound) => {}
            other => return other.map(Some),
        }
        let signer = match persistence::load_policy(storage) {
            Err(KeepMobileError::StorageNotFound) => return Ok(None),
            Ok(bundle) if bundle.verify_signature().is_ok() && bundle.verify_hash().is_ok() => {
                bundle.warden_pubkey
            }
            Ok(_) | Err(KeepMobileError::InvalidPolicy { .. }) => {
                return Err(KeepMobileError::StorageError {
                    msg: "The trusted wardens record is missing beside a stored policy that \
                          does not verify; wipe the app data to recover"
                        .into(),
                })
            }
            // A read that failed may succeed on the next call, so it is
            // reported as it is rather than as a reason to wipe.
            Err(e) => return Err(e),
        };
        let set = persistence::WardenSet {
            wardens: std::collections::HashSet::from([signer]),
            epoch: 0,
            device: Some(keep_core::crypto::try_random_bytes::<32>()?),
            restored: true,
        };
        persistence::persist_warden_set(storage, &set)?;
        tracing::warn!("Trusted wardens record was lost; restored from the stored policy's signer");
        Ok(Some(set))
    }

    fn next_epoch(epoch: u64) -> Result<u64, KeepMobileError> {
        epoch
            .checked_add(1)
            .ok_or_else(|| KeepMobileError::InvalidPolicy {
                msg: "The warden epoch is exhausted".into(),
            })
    }

    /// Load the persisted NIP-46 bunker permission grants from the global relay
    /// config, returning them ready to seed `ServerConfig::pre_grants` so
    /// remembered grants survive a bunker restart. Only grants made under
    /// `scope` are returned: a client remembered before a credential rotation,
    /// or for another share, has to be approved again.
    pub(crate) fn load_bunker_permissions(
        &self,
        scope: &str,
    ) -> Vec<keep_core::relay::StoredBunkerPermission> {
        let key = relay_config_key(None);
        match persistence::load_relay_config(&self.storage, &key) {
            Ok(Some(c)) if c.bunker_permissions_scope.as_deref() == Some(scope) => {
                c.bunker_permissions
            }
            Ok(Some(c)) => {
                if !c.bunker_permissions.is_empty() {
                    tracing::info!(
                        "not restoring bunker grants made under other bunker credentials or another share"
                    );
                }
                Vec::new()
            }
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

    /// Replace the persisted NIP-46 bunker permission grants with `grants`, made
    /// under `scope` (see `load_bunker_permissions`), preserving the relay
    /// lists. Called from the engine's `persist_permissions` callback after
    /// every grant write or revoke, so the durable store mirrors the in-memory
    /// engine (the single source of truth). Nothing is written unless `serving`
    /// holds once the lock is taken: a server still winding down after a stop
    /// would otherwise write back grants a revoke cleared in the meantime.
    pub(crate) fn persist_bunker_permissions(
        &self,
        grants: Vec<keep_core::relay::StoredBunkerPermission>,
        scope: &str,
        serving: impl FnOnce() -> bool,
    ) -> Result<(), KeepMobileError> {
        let key = relay_config_key(None);
        let _guard = self
            .relay_config_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !serving() {
            tracing::debug!("not persisting bunker grants from a stopped server");
            return Ok(());
        }
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
        stored.bunker_permissions_scope = Some(scope.to_owned());
        persistence::persist_relay_config(&self.storage, &key, &stored)
    }

    /// Drop the persisted NIP-46 grants of `client`, or of every client when
    /// `None`, so a revoke holds when no bunker is running to persist it.
    pub(crate) fn forget_bunker_permissions(
        &self,
        client: Option<&nostr_sdk::PublicKey>,
    ) -> Result<(), KeepMobileError> {
        let key = relay_config_key(None);
        let _guard = self
            .relay_config_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut stored = match persistence::load_relay_config(&self.storage, &key) {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(()),
            Err(e) => {
                return Err(KeepMobileError::StorageError {
                    msg: format!("failed to load existing relay config: {e}"),
                });
            }
        };
        let before = stored.bunker_permissions.len();
        match client {
            Some(client) => stored.bunker_permissions.retain(|grant| {
                nostr_sdk::PublicKey::from_hex(&grant.pubkey_hex)
                    .ok()
                    .as_ref()
                    != Some(client)
            }),
            None => stored.bunker_permissions.clear(),
        }
        if stored.bunker_permissions.len() == before {
            return Ok(());
        }
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

    /// The loopback SOCKS proxy relay sockets go through, when one is enabled.
    pub(crate) fn configured_proxy(&self) -> Result<Option<std::net::SocketAddr>, KeepMobileError> {
        let stored = persistence::load_proxy_config(&self.storage, PROXY_CONFIG_STORAGE_KEY)?
            .unwrap_or_default();
        if stored.enabled {
            Ok(Some(parse_loopback_proxy("127.0.0.1", stored.port)?))
        } else {
            Ok(None)
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
            let share_of = |node: &KfpNode| {
                let metadata = &node.share_package().metadata;
                (metadata.group_pubkey, metadata.identifier)
            };
            let prior_share = self.node.read().await.as_deref().map(share_of);
            let loaded_share = share_of(&node);
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
            // A bunker started on a different share holds a copy of it, or the
            // node built from it, so it stops as on any other teardown, after
            // the write as there. A re-init on the same share, which the app
            // does on every network change, leaves it running.
            if prior_share.is_some_and(|prior| prior != loaded_share) {
                self.live_generation
                    .send_modify(|generation| *generation = generation.wrapping_add(1));
            }
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

    /// The time to judge policy validity at, never earlier than the floor.
    ///
    /// `now_elapsed_ms` is the platform's monotonic reading, as
    /// [`SigningRateLimiter::check_and_record`] already takes. `None` means the
    /// caller has none, which consults the floor without advancing it: raising
    /// it needs proof that time passed, and reading it does not.
    ///
    /// A floor that cannot be read is an error, not an absence. Nothing then
    /// says the clock was not wound back, and the callers turn that into a
    /// refusal, because the alternative is trusting the one input this exists
    /// to distrust.
    ///
    /// [`SigningRateLimiter::check_and_record`]: crate::SigningRateLimiter::check_and_record
    fn policy_now(
        &self,
        now_elapsed_ms: Option<u64>,
    ) -> Result<clock_floor::PolicyClock, KeepMobileError> {
        // One read-modify-write at a time. Two calls racing through the load
        // and the store would each observe the same old floor and the later
        // store would win, losing the other's advance; with the floor resting
        // on that record, a lost advance is a wider rewind window. Taken before
        // the policy lock and never while it is held, so the order is fixed.
        let _floor = FLOOR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::floor_now(&self.storage, now_elapsed_ms, || {
            // A poisoned lock answers "configured", which keeps the corrupt
            // record and refuses rather than replacing it.
            !self.policy_configured().unwrap_or(true)
        })
    }

    /// [`Self::policy_now`] before there is a `self`, for the load the
    /// constructor does. Locked like any other call: nothing can call into
    /// this instance before it exists, but another instance on the same
    /// storage can be running.
    fn startup_policy_now(
        storage: &Arc<dyn SecureStorage>,
    ) -> Result<clock_floor::PolicyClock, KeepMobileError> {
        let _floor = FLOOR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::floor_now(storage, None, || {
            matches!(
                persistence::load_policy(storage),
                Err(KeepMobileError::StorageNotFound)
            )
        })
    }

    /// `no_policy` is asked only when the stored floor is corrupt, and decides
    /// whether it may be replaced.
    ///
    /// With no policy configured the floor guards nothing, so a corrupt record
    /// is replaced with a fresh one. Refusing instead would leave it in place
    /// forever, since nothing else rewrites it, and the device could never
    /// install a policy again: deleting the old policy, which is the way out of
    /// every other fault, would not help. With a policy configured it refuses,
    /// because then the record is the only thing saying the clock was not wound
    /// back; deleting the policy is the way out, after which the next call
    /// replaces it.
    fn floor_now(
        storage: &Arc<dyn SecureStorage>,
        now_elapsed_ms: Option<u64>,
        no_policy: impl FnOnce() -> bool,
    ) -> Result<clock_floor::PolicyClock, KeepMobileError> {
        let now_secs = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let fresh = || clock_floor::ClockFloor::new(now_secs, now_elapsed_ms);
        let (floor, first_write) = match persistence::load_clock_floor(storage) {
            Ok(persistence::ClockFloorRead::Found(floor)) => (floor, false),
            Ok(persistence::ClockFloorRead::Absent) => (fresh(), true),
            // A record that will not parse, or will not read, is replaced when
            // no policy depends on it, and both for the same reason. A read
            // that fails is not only transient: a record whose key alias was
            // invalidated comes back as an error (see `load_share_by_key`) and
            // never recovers, so refusing on it would lock a device out of
            // installing a policy for good, exactly as a corrupt one did. With
            // no policy the floor's only job is judging an import, and
            // installing any bundle is never looser than having none.
            _ if no_policy() => {
                tracing::warn!("Replacing an unusable time floor; no policy depends on it");
                (fresh(), true)
            }
            // With a policy the record is the only thing saying the clock was
            // not wound back, so it refuses. A corrupt one is reported as
            // `InvalidPolicy`, which the callers map to a fault that is not
            // retried, because it will not clear; a failed read keeps its own
            // error, which they map to one that is.
            Ok(persistence::ClockFloorRead::Corrupt) => {
                return Err(KeepMobileError::InvalidPolicy {
                    msg: "The time floor is corrupt and a policy depends on it".into(),
                })
            }
            Err(e) => return Err(floor_storage_error(e)),
        };
        let (observed, changed) = floor.observe(now_secs, now_elapsed_ms);
        if changed || first_write {
            persistence::persist_clock_floor(storage, &observed).map_err(floor_storage_error)?;
        }
        Ok(observed.clock_at(now_secs))
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
    /// policy". Construction rebuilds a lost record from the bundle's signer
    /// before this runs, so absent here means that rebuild could not happen.
    fn load_policy_into(
        storage: &Arc<dyn SecureStorage>,
        evaluator: &mut PolicyEvaluator,
        clock: clock_floor::PolicyClock,
    ) {
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
            Err(_) => tracing::error!(
                "Trusted wardens unreadable, keeping the set already in memory; a \
                 stored policy needing a warden outside it will refuse"
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
            Err(KeepMobileError::InvalidPolicy { .. }) => {
                tracing::error!("Stored policy could not be parsed, every rule will refuse");
                evaluator.set_policy_faulted(PolicyFault::Unverified, None);
                return;
            }
            Err(_) => {
                tracing::error!("Policy unreadable, every rule will refuse");
                evaluator.set_policy_faulted(PolicyFault::Unreadable, None);
                return;
            }
        };

        // Attribution before the clock, and in that order deliberately. The
        // signature, hash and signer are what make the bundle evidence; only
        // once they hold is its own `created_at` worth anything, which is what
        // lets a replacement be measured against an expired bundle rather than
        // the expired one having to be thrown away first.
        //
        // Each arm logs a fixed string naming the check, not the error. The
        // error's `Display` drops its `msg` anyway, so `{e}` would print
        // "Invalid policy bundle" for all three and leave a hash mismatch, a
        // forged signature and an untrusted signer indistinguishable; the
        // `msg` itself must not be logged, because it can quote the record.
        let attributed = if bundle.verify_signature().is_err() {
            Err("signature")
        } else if bundle.verify_hash().is_err() {
            Err("hash")
        } else if bundle
            .verify_trusted_warden(evaluator.trusted_wardens())
            .is_err()
        {
            Err("no trusted signer")
        } else {
            Ok(())
        };
        if let Err(check) = attributed {
            tracing::error!("Stored policy did not verify ({check}), every rule will refuse");
            evaluator.set_policy_faulted(PolicyFault::Unverified, None);
            return;
        }

        match bundle.timestamp_fault_at(clock) {
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
    fn reload_policy_if_transient(
        &self,
        clock: clock_floor::PolicyClock,
    ) -> Result<(), KeepMobileError> {
        // Bound to a local first. Folding this into the `if` condition, or into
        // a `match`, keeps the read guard alive across `policy_write_lock` and
        // self-deadlocks on a lock that is not reentrant.
        let fault = self.policy_read_lock()?.fault();
        if !fault.is_some_and(PolicyFault::is_transient) {
            return Ok(());
        }
        let mut policy = self.policy_write_lock()?;
        Self::load_policy_into(&self.storage, &mut policy, clock);
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
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
            fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
                match self.get_active_share_key() {
                    Some(value) => crate::signing_policy::StorageRead::Found { value },
                    None => crate::signing_policy::StorageRead::Absent,
                }
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
            fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
                match self.get_active_share_key() {
                    Some(value) => crate::signing_policy::StorageRead::Found { value },
                    None => crate::signing_policy::StorageRead::Absent,
                }
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

    // The legacy single-share delete tears the live node down like the keyed
    // one, so a running bunker does not sign on with the deleted share.
    #[test]
    fn the_legacy_share_delete_tears_the_live_node_down() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage)).unwrap();
        let invalidated = mobile.live_generation.subscribe();
        mobile.delete_share().unwrap();
        assert!(invalidated.has_changed().unwrap());
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
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
        /// The active-share pointer fails to read: its getter answers `None`,
        /// as Android's does on a fault.
        pointer_unreadable: std::sync::atomic::AtomicBool,
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
        // Only writes that carry a group are shares, as on a platform store;
        // the policy and descriptor records go through the same method.
        fn list_all_shares(&self) -> Vec<ShareMetadataInfo> {
            self.metas
                .lock()
                .unwrap()
                .iter()
                .filter(|m| !m.group_pubkey.is_empty())
                .cloned()
                .collect()
        }
        fn delete_share_by_key(&self, key: String) -> Result<(), KeepMobileError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
        fn get_active_share_key(&self) -> Option<String> {
            if self
                .pointer_unreadable
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return None;
            }
            self.active.lock().unwrap().clone()
        }
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            if self
                .pointer_unreadable
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return crate::signing_policy::StorageRead::Unavailable;
            }
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
            fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
                match self.get_active_share_key() {
                    Some(value) => crate::signing_policy::StorageRead::Found { value },
                    None => crate::signing_policy::StorageRead::Absent,
                }
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

    // An unreadable descriptor index refuses every descriptor save and delete,
    // and must not cost the shares their backup as well. The descriptor of a
    // group held here still goes into the backup, read without the index, and
    // the reset lets descriptor writes through again.
    #[test]
    fn an_unreadable_descriptor_index_still_backs_up_and_can_be_reset() {
        let group = [7u8; 32];
        let pass = "correct horse battery staple";
        let bytes = keep_core::backup::create_backup_from_data(
            vec![],
            vec![backup_share(true)],
            [group, [8u8; 32]]
                .map(|group_pubkey| keep_core::wallet::WalletDescriptor {
                    group_pubkey,
                    external_descriptor: "wpkh(xpub.../0/*)".into(),
                    internal_descriptor: "wpkh(xpub.../1/*)".into(),
                    network: "bitcoin".into(),
                    created_at: 1_700_000_000,
                    device_registrations: vec![],
                    policy_hash: [9u8; 32],
                    version: 1,
                    previous_descriptor_hash: None,
                    policy: None,
                })
                .to_vec(),
            vec![],
            vec![],
            keep_core::backup::BackupConfig {
                kill_switch: false,
                proxy: None,
            },
            vec![],
            pass,
        )
        .expect("backup should build");
        let storage = Arc::new(RecordingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        mobile.restore_backup(bytes, pass.into()).unwrap();
        assert_eq!(mobile.wallet_descriptor_list().len(), 2);

        storage
            .data
            .lock()
            .unwrap()
            .insert(DESCRIPTOR_INDEX_KEY.into(), b"not json".to_vec());
        assert!(mobile.wallet_descriptor_delete(hex::encode(group)).is_err());

        let backup = mobile
            .create_backup(pass.into())
            .expect("an unreadable index must not deny the share backup");
        let decrypted = decrypt_backup_data(&backup, pass).unwrap();
        assert_eq!(decrypted.shares.len(), 1);
        assert_eq!(
            decrypted.wallet_descriptors.len(),
            1,
            "only the held group's descriptor is read without the index"
        );
        assert_eq!(decrypted.wallet_descriptors[0].group_pubkey, group);

        assert!(mobile.wallet_descriptor_repair_index(false).is_err());
        assert_eq!(mobile.wallet_descriptor_repair_index(true).unwrap(), 1);
        assert_eq!(mobile.wallet_descriptor_list().len(), 1);
        mobile
            .wallet_descriptor_delete(hex::encode(group))
            .expect("writes go through once the index is reset");
        assert!(mobile.wallet_descriptor_list().is_empty());
    }

    // A restore while the active-share pointer cannot be read leaves it as it
    // is: it may name another account, and repointing it would switch accounts
    // without the cleanup a switch needs.
    #[test]
    fn a_restore_leaves_an_unreadable_active_share_alone() {
        let bytes = keep_core::backup::create_backup_from_data(
            vec![],
            vec![backup_share(true)],
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
        let other = hex::encode([9u8; 32]);
        *storage.active.lock().unwrap() = Some(other.clone());
        storage
            .pointer_unreadable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        mobile
            .restore_backup(bytes, "correct horse battery staple".into())
            .expect("restore should succeed");
        assert_eq!(*storage.active.lock().unwrap(), Some(other));
    }

    // Whether the share being deleted is the active one decides whether the
    // pointer goes with it, so a pointer that cannot be read refuses the delete.
    #[test]
    fn a_delete_with_an_unreadable_active_share_is_refused() {
        let (storage, _) = restore_one(true);
        let key = hex::encode([7u8; 32]);
        assert_eq!(*storage.active.lock().unwrap(), Some(key.clone()));
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        storage
            .pointer_unreadable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(mobile.delete_share_by_key(key.clone()).is_err());
        assert!(
            storage.load_share_by_key(key.clone()).is_ok(),
            "nothing deleted"
        );
        assert_eq!(*storage.active.lock().unwrap(), Some(key));
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
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
        /// Reads of these fault with `InvalidPolicy`, which the storage error
        /// type admits, to pin that a caller does not read meaning into it.
        misreported: StdMutex<Vec<String>>,
        /// Reads of a key fault once it has been read this many times, to
        /// fail a read-back that follows a successful read and write.
        fault_from_read: StdMutex<HashMap<String, usize>>,
        unwritable: StdMutex<Vec<String>>,
        undeletable: StdMutex<Vec<String>>,
        reads: StdMutex<HashMap<String, usize>>,
    }

    impl FaultingStorage {
        /// Fault reads of `key` from the one after the next `after`, counting
        /// from now.
        fn fault_after_reads(&self, key: &str, after: usize) {
            let so_far = self.reads_of(key);
            self.fault_from_read
                .lock()
                .unwrap()
                .insert(key.into(), so_far + after + 1);
        }

        fn fault(&self, key: &str) {
            self.unreadable.lock().unwrap().push(key.into());
        }

        fn misreport(&self, key: &str) {
            self.misreported.lock().unwrap().push(key.into());
        }

        fn fault_write(&self, key: &str) {
            self.unwritable.lock().unwrap().push(key.into());
        }

        fn heal(&self) {
            self.unreadable.lock().unwrap().clear();
            self.unwritable.lock().unwrap().clear();
            self.fault_from_read.lock().unwrap().clear();
        }

        fn heal_delete(&self) {
            self.undeletable.lock().unwrap().clear();
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
            let reads = {
                let mut reads = self.reads.lock().unwrap();
                let count = reads.entry(key.clone()).or_insert(0);
                *count += 1;
                *count
            };
            if self
                .fault_from_read
                .lock()
                .unwrap()
                .get(&key)
                .is_some_and(|&from| reads >= from)
            {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot decrypt right now".into(),
                });
            }
            if self.unreadable.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::StorageError {
                    msg: "cannot decrypt right now".into(),
                });
            }
            if self.misreported.lock().unwrap().contains(&key) {
                return Err(KeepMobileError::InvalidPolicy {
                    msg: "reported by storage".into(),
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
        fn read_active_share_key(&self) -> crate::signing_policy::StorageRead {
            match self.get_active_share_key() {
                Some(value) => crate::signing_policy::StorageRead::Found { value },
                None => crate::signing_policy::StorageRead::Absent,
            }
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
            .evaluate_policy(
                TransactionContext {
                    amount_sats: 1,
                    fee_sats: 1,
                    destinations: vec![],
                    has_unknown_destination: false,
                },
                None,
            )
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
        MAX_POLICY_AGE_SECS, MAX_POLICY_FUTURE_SECS, POLICY_VERSION,
    };
    use chrono::Utc;

    fn plant_policy(storage: &FaultingStorage, rules: &PolicyRules, trust_warden: bool) -> Vec<u8> {
        plant_signed_policy(storage, rules, trust_warden)
            .1
            .warden_pubkey
            .to_vec()
    }

    fn new_warden() -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng)
    }

    fn pubkey_of(key: &k256::schnorr::SigningKey) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&key.verifying_key().to_bytes());
        out
    }

    /// `plant_policy`, keeping the warden's signing key so a test can sign the
    /// authorizations that removing the policy or changing wardens now needs.
    fn plant_signed_policy(
        storage: &FaultingStorage,
        rules: &PolicyRules,
        trust_warden: bool,
    ) -> (k256::schnorr::SigningKey, crate::policy::PolicyBundle) {
        let key = new_warden();
        let bundle = create_test_bundle_with(&key, rules, Utc::now().timestamp() as u64);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&bundle).expect("serialize policy"),
        );
        if trust_warden {
            storage.plant(
                TRUSTED_WARDENS_KEY,
                serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)])
                    .expect("serialize wardens"),
            );
        }
        (key, bundle)
    }

    /// The device id and epoch the next authorization has to name.
    fn governance(mobile: &KeepMobile) -> ([u8; 32], u64) {
        let governance = mobile.warden_governance().unwrap();
        let device = hex::decode(governance.device_id)
            .unwrap()
            .try_into()
            .unwrap();
        (device, governance.epoch)
    }

    /// A revocation of `subject`, signed by `key` at the device's current epoch.
    fn revocation(
        mobile: &KeepMobile,
        key: &k256::schnorr::SigningKey,
        subject: &[u8; 32],
    ) -> String {
        let (device, epoch) = governance(mobile);
        crate::warden_auth::sign_authorization(
            key,
            crate::warden_auth::WardenAction::RevokePolicy,
            subject,
            &device,
            epoch,
        )
    }

    /// An authorization from `key` to add or remove `warden`, at the current
    /// epoch.
    fn warden_change(
        mobile: &KeepMobile,
        key: &k256::schnorr::SigningKey,
        action: crate::warden_auth::WardenAction,
        warden: &[u8; 32],
    ) -> String {
        let (device, epoch) = governance(mobile);
        crate::warden_auth::sign_authorization(key, action, warden, &device, epoch)
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

        let PolicyDecision::Deny { reason } = mobile.evaluate_policy(a_spend(), None).unwrap()
        else {
            panic!("a tampered policy record must refuse, not allow everything");
        };
        assert!(reason.contains("policy"), "{reason}");
        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Faulted { .. }
            ),
            "the refusal has to be explainable, so it must not report as unconfigured"
        );
        assert!(mobile.get_policy_info(None).is_none());
    }

    /// A verified record still works, so the refusals above cannot be a policy
    /// engine that simply says no.
    #[test]
    fn a_verified_policy_record_is_enforced() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Allow
        );
        let over = TransactionContext {
            amount_sats: 200_000,
            ..a_spend()
        };
        assert!(matches!(
            mobile.evaluate_policy(over, None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// No record at all is the one state that means there are no rules.
    #[test]
    fn no_policy_record_allows() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(storage as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
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
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unreadable
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        storage.heal();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
        assert_eq!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Allow
        );
    }

    /// A wardens record lost beside a stored policy, as a power loss can do to
    /// one file and not the other, is rebuilt from the policy's signer. The
    /// policy stays in force rather than refusing until a wipe, and the new
    /// device id leaves nothing signed before the loss usable.
    #[test]
    fn a_lost_wardens_record_is_restored_from_the_policy_signer() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let before = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let (device_before, _) = governance(&before);
        let held = revocation(&before, &warden, &bundle.digest());
        assert!(!before.warden_governance().unwrap().restored);
        storage.records.lock().unwrap().remove(TRUSTED_WARDENS_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(bundle.warden_pubkey)]
        );
        let (device, epoch) = governance(&mobile);
        assert_ne!(device, device_before);
        assert_eq!(epoch, 0);
        assert!(mobile.warden_governance().unwrap().restored);

        let relaunched = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert_eq!(governance(&relaunched), (device, 0));
        assert!(relaunched.warden_governance().unwrap().restored);

        assert!(mobile.delete_policy(Some(held)).is_err());
        let fresh = revocation(&mobile, &warden, &bundle.digest());
        mobile.delete_policy(Some(fresh)).unwrap();
        assert!(!mobile.warden_governance().unwrap().restored);
    }

    /// A policy that does not verify names no signer, so a lost wardens record
    /// beside one is not rebuilt, and not replaced by an empty set either,
    /// which would leave the policy with nothing able to revoke it.
    #[test]
    fn a_lost_wardens_record_beside_an_unverified_policy_stays_refused() {
        let storage = Arc::new(FaultingStorage::default());
        plant_signed_policy(&storage, &capped_rules(), false);
        let text = String::from_utf8(storage.raw(POLICY_STORAGE_KEY).unwrap()).unwrap();
        let edited = text.replace("100000", "900000");
        assert_ne!(edited, text, "the fixture must contain the cap to edit");
        storage.plant(POLICY_STORAGE_KEY, edited.into_bytes());

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted { .. }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
        assert!(mobile.warden_governance().is_err());
        assert!(storage.raw(TRUSTED_WARDENS_KEY).is_none());
    }

    /// The lockout this refusal could otherwise cause has a way out that keeps
    /// the rules: trust the signer and the stored bundle verifies again. This is
    /// the warden-rotation path, and it is why refusing an unattributable policy
    /// does not require throwing it away.
    #[test]
    fn trusting_the_warden_brings_the_stored_policy_back_into_force() {
        // A key rotation: the policy is signed by a new key the device does not
        // trust yet, and the warden it does trust authorizes that key.
        let storage = Arc::new(FaultingStorage::default());
        let (_rotated, bundle) = plant_signed_policy(&storage, &capped_rules(), false);
        let trusted = new_warden();
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&trusted))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted { .. }
        ));

        let add = warden_change(
            &mobile,
            &trusted,
            crate::warden_auth::WardenAction::AddWarden,
            &bundle.warden_pubkey,
        );
        mobile
            .add_trusted_warden(hex::encode(bundle.warden_pubkey), Some(add))
            .unwrap();

        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Active { .. }
            ),
            "trusting the signer must re-run the stored policy, not leave it faulted"
        );
        let over = TransactionContext {
            amount_sats: 200_000,
            ..a_spend()
        };
        assert!(matches!(
            mobile.evaluate_policy(over, None).unwrap(),
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
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
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
        assert!(msg.contains("revoke the stored policy first"), "{msg}");

        // While the record will not read, nothing can say it is that bundle,
        // so a revocation naming its digest does not apply. The fault is never
        // healed here: a record whose key alias was invalidated never reads
        // again, and the warden's revocation of an unreadable policy has to be
        // the way out of it.
        assert!(mobile
            .delete_policy(Some(revocation(&mobile, &warden, &bundle.digest())))
            .is_err());
        assert!(mobile.delete_policy(None).is_err());
        mobile
            .delete_policy(Some(revocation(
                &mobile,
                &warden,
                &crate::warden_auth::unreadable_policy_subject(),
            )))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
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
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// The warden set survives a record that cannot be read back after a
    /// change. Without that, adding a warden would persist it and then lose it
    /// on the very reload meant to put the policy back in force, so the
    /// rotation would fail exactly when storage is already misbehaving.
    #[test]
    fn adding_a_warden_survives_a_wardens_record_that_cannot_be_read_back() {
        let storage = Arc::new(FaultingStorage::default());
        let (_rotated, bundle) = plant_signed_policy(&storage, &capped_rules(), false);
        let trusted = new_warden();
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&trusted))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted { .. }
        ));

        let add = warden_change(
            &mobile,
            &trusted,
            crate::warden_auth::WardenAction::AddWarden,
            &bundle.warden_pubkey,
        );
        // The change reads the record once to check the epoch; the read-back
        // in the reload that follows the write is the one that fails.
        storage.fault_after_reads(TRUSTED_WARDENS_KEY, 1);
        let reads_before = storage.reads_of(TRUSTED_WARDENS_KEY);
        mobile
            .add_trusted_warden(hex::encode(bundle.warden_pubkey), Some(add))
            .unwrap();
        assert_eq!(
            storage.reads_of(TRUSTED_WARDENS_KEY),
            reads_before + 2,
            "the read-back must actually have been attempted and failed"
        );

        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Active { .. }
            ),
            "the warden just added must not be dropped by the reload that follows it"
        );
        let mut listed = mobile.list_trusted_wardens().unwrap();
        listed.sort();
        let mut expected = vec![
            hex::encode(pubkey_of(&trusted)),
            hex::encode(bundle.warden_pubkey),
        ];
        expected.sort();
        assert_eq!(listed, expected);
    }

    /// A change to the wardens is refused while their record cannot be read,
    /// because the epoch that stops an authorization being replayed lives in
    /// that record, and without it there is no saying whether this one was
    /// already used.
    #[test]
    fn changing_wardens_is_refused_while_their_record_cannot_be_read() {
        let storage = Arc::new(FaultingStorage::default());
        let (_rotated, bundle) = plant_signed_policy(&storage, &capped_rules(), false);
        let trusted = new_warden();
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&trusted))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let add = warden_change(
            &mobile,
            &trusted,
            crate::warden_auth::WardenAction::AddWarden,
            &bundle.warden_pubkey,
        );

        storage.fault(TRUSTED_WARDENS_KEY);
        assert!(mobile
            .add_trusted_warden(hex::encode(bundle.warden_pubkey), Some(add))
            .is_err());
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
            mobile.policy_status(None).unwrap(),
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
                mobile.evaluate_policy(over, None).unwrap(),
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
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
        let after_load = storage.reads_of(POLICY_STORAGE_KEY);
        for _ in 0..5 {
            assert!(matches!(
                mobile.evaluate_policy(a_spend(), None).unwrap(),
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
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::NotYetValid
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        let after_load = storage.reads_of(POLICY_STORAGE_KEY);
        mobile.evaluate_policy(a_spend(), None).unwrap();
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
        // The warden renewing its own policy, which needs no change to the
        // trusted set.
        let warden = new_warden();
        let old = create_test_bundle_with(&warden, &capped_rules(), long_ago);
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&old).unwrap());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(old.warden_pubkey)]).unwrap(),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Expired
            }
        ));
        assert!(
            matches!(
                mobile.evaluate_policy(a_spend(), None).unwrap(),
                PolicyDecision::Deny { .. }
            ),
            "stale rules are neither enforced nor ignored"
        );

        let fresh = create_test_bundle_with(
            &warden,
            &capped_rules(),
            chrono::Utc::now().timestamp() as u64,
        );
        mobile
            .import_policy(hex::encode(fresh.to_bytes()))
            .expect("a replacement must install over an expired policy");

        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// The escape hatch must not report success on a delete that did not
    /// happen: memory would open the gate for this process while the record
    /// stayed put and faulted again at the next launch.
    #[test]
    fn a_delete_that_fails_leaves_the_policy_refusing() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        storage.fault_delete(POLICY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        // A valid revocation, so the refusal is the storage delete failing and
        // not anything before it.
        let revoke = revocation(&mobile, &warden, &bundle.digest());
        assert!(mobile.delete_policy(Some(revoke.clone())).is_err());
        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Active { .. }
            ),
            "a failed delete must not leave memory reading as no policy"
        );

        // And the revocation was spent before the delete was tried, so it
        // cannot be used again once storage recovers; a new one is needed.
        storage.heal_delete();
        assert!(mobile.delete_policy(Some(revoke)).is_err());
        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &bundle.digest())))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
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
            mobile.policy_status(None).unwrap(),
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
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// A policy that could not be stored must not take effect. Committing to
    /// memory before the write means a failed persist returns an error while
    /// the process enforces the bundle anyway, and on a faulted record that is
    /// a deny-all lifted by a write that never landed.
    #[test]
    fn a_policy_that_cannot_be_stored_does_not_take_effect() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let stale =
            create_test_bundle_with(&warden, &capped_rules(), now - MAX_POLICY_AGE_SECS - 3600);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&stale).expect("serialize policy"),
        );
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(stale.warden_pubkey)]).expect("serialize wardens"),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Expired
            }
        ));

        storage.fault_write(POLICY_STORAGE_KEY);
        let replacement = create_test_bundle_with(&warden, &PolicyRules::default(), now);
        mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .expect_err("an unstorable policy must not install");

        // The refusal has to outlive the failed write, or the gate is open for
        // the life of the process on a policy storage never accepted.
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted { .. }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// The rollback check has to run against the stored bundle, not against
    /// nothing. Without the baseline an older warden-signed bundle installs
    /// over a newer one.
    #[test]
    fn an_older_bundle_cannot_be_installed_over_the_stored_one() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let current = create_test_bundle_with(&warden, &capped_rules(), now);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&current).expect("serialize policy"),
        );
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(current.warden_pubkey)])
                .expect("serialize wardens"),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));

        let older = create_test_bundle_with(&warden, &PolicyRules::default(), now - 3600);
        let err = mobile
            .import_policy(hex::encode(older.to_bytes()))
            .expect_err("an older bundle must not install over a newer one");
        let KeepMobileError::InvalidPolicy { msg } = err else {
            panic!("expected a downgrade refusal, got {err:?}");
        };
        assert!(msg.contains("Cannot downgrade"), "{msg}");
    }

    /// A warden the device could not record must not be trusted in memory
    /// either. One that is would attribute a stored bundle to a signer this
    /// process trusts and the next one does not.
    #[test]
    fn a_warden_that_cannot_be_stored_is_not_trusted() {
        let storage = Arc::new(FaultingStorage::default());
        let (_rotated, bundle) = plant_signed_policy(&storage, &capped_rules(), false);
        let trusted = new_warden();
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&trusted))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let add = warden_change(
            &mobile,
            &trusted,
            crate::warden_auth::WardenAction::AddWarden,
            &bundle.warden_pubkey,
        );

        storage.fault_write(TRUSTED_WARDENS_KEY);
        let err = mobile
            .add_trusted_warden(hex::encode(bundle.warden_pubkey), Some(add))
            .expect_err("a warden that cannot be persisted must not be trusted");
        assert!(
            matches!(err, KeepMobileError::StorageError { .. }),
            "refused for the write, not the authorization: {err:?}"
        );

        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(pubkey_of(&trusted))],
            "memory must not hold a warden storage refused"
        );
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted { .. }
        ));
    }

    /// A bundle dated ahead of the clock is attributed and still not a
    /// baseline. Treating it as one measures every honestly dated replacement
    /// against a time that has not happened, so all of them read as downgrades
    /// and the device can only be recovered by discarding the policy.
    #[test]
    fn a_future_dated_policy_does_not_refuse_its_own_replacement() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let ahead = create_test_bundle_with(
            &warden,
            &capped_rules(),
            now + MAX_POLICY_FUTURE_SECS + 3600,
        );
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&ahead).expect("serialize policy"),
        );
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(ahead.warden_pubkey)]).expect("serialize wardens"),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::NotYetValid
            }
        ));

        let replacement = create_test_bundle_with(&warden, &PolicyRules::default(), now);
        let err = mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .expect_err("a future-dated record cannot be checked against");
        let KeepMobileError::InvalidPolicy { msg } = err else {
            panic!("expected the fault refusal, got {err:?}");
        };
        // The actionable refusal, not "Cannot downgrade": the stored record is
        // the problem, and deleting it is what the caller can do about it.
        assert!(msg.contains("revoke the stored policy first"), "{msg}");

        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &ahead.digest())))
            .unwrap();
        mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .expect("a correctly dated bundle must install once the record is gone");
    }

    /// An oversized stored record is refused before it is parsed.
    ///
    /// The padding sits in a field the bundle does not declare, so serde
    /// ignores it and the rules themselves stay inside their own cap: without
    /// the length check ahead of the parse this record verifies and loads. That
    /// is what makes this a test of the pre-parse bound rather than of the
    /// rules-field bound, which catches a different record.
    #[test]
    fn an_oversized_policy_record_is_refused() {
        let storage = Arc::new(FaultingStorage::default());
        let bundle = create_test_bundle(&capped_rules());
        let mut record: serde_json::Value = serde_json::to_value(&bundle).unwrap();
        record
            .as_object_mut()
            .unwrap()
            .insert("padding".into(), serde_json::json!("x".repeat(64 * 1024)));
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&record).unwrap());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)])
                .expect("serialize wardens"),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
    }

    /// A record whose version this build does not know faults rather than being
    /// enforced under the rule semantics of a different version.
    #[test]
    fn a_stored_policy_of_an_unknown_version_faults() {
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let mut bundle =
            create_test_bundle_with(&warden, &capped_rules(), Utc::now().timestamp() as u64);
        bundle.version = POLICY_VERSION + 1;
        // Signed at the new version, so the signature holds and the version
        // gate is the only thing that can refuse this record. Without the
        // re-signing the altered version breaks the signature and the test
        // passes whether the gate exists or not.
        crate::policy::resign_test_bundle(&warden, &mut bundle);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&bundle).expect("serialize policy"),
        );
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)])
                .expect("serialize wardens"),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));
    }

    /// A counters record holding more than the cap is refused, not trimmed.
    /// Trimming on load is the shape that let a moved clock erase the history,
    /// and the counters already deny every rule that depends on them while they
    /// are unknown.
    #[test]
    fn an_over_capacity_velocity_record_refuses_rather_than_being_trimmed() {
        use crate::velocity::MAX_TRACKED_TRANSACTIONS;

        let storage = Arc::new(FaultingStorage::default());
        let mut tracker = VelocityTracker::new();
        for _ in 0..MAX_TRACKED_TRANSACTIONS + 1 {
            tracker.record(1);
        }
        // `record` enforces the cap, so the over-capacity record has to be
        // built by hand: this is a record that arrived from somewhere the cap
        // was not applied.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&tracker.to_bytes().expect("serialize")).unwrap();
        let entries = raw
            .get_mut("transactions")
            .and_then(|t| t.as_array_mut())
            .expect("transactions array");
        let one = entries[0].clone();
        while entries.len() <= MAX_TRACKED_TRANSACTIONS {
            entries.push(one.clone());
        }
        storage.plant(VELOCITY_STORAGE_KEY, serde_json::to_vec(&raw).unwrap());

        let rules = PolicyRules {
            daily_limit: Some(100_000),
            ..Default::default()
        };
        plant_policy(&storage, &rules, true);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// Winding the device clock back must not put an expired policy back in
    /// force. The stored floor is the time already known to have passed, so
    /// validity is judged against it rather than against the date setting.
    ///
    /// The attack cannot be staged by moving the real clock under test, so it
    /// is staged from the other side: the bundle is dated now, and the floor
    /// says a time past its window has already been observed, which is the same
    /// relation as a bundle whose window closed while the clock was later and
    /// has now been wound back inside it.
    #[test]
    fn a_clock_wound_back_does_not_revive_an_expired_policy() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        // Past the thirty-day window, and the anchor is ahead of the reading
        // the test passes in, so the reload takes the reboot path and leaves
        // the floor where it was planted.
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor {
                floor_secs: now + 40 * 24 * 3600,
                anchor_elapsed_ms: Some(5_000),
            })
            .unwrap(),
        );

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Faulted {
                    fault: PolicyFault::Expired
                }
            ),
            "a bundle whose window closed against the floor must stay expired"
        );
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        // And it cannot be reinstalled by the same wound-back clock: the import
        // is judged against the floor too.
        let bundle = create_test_bundle(&capped_rules());
        mobile
            .import_policy(hex::encode(bundle.to_bytes()))
            .expect_err("an import judged against the floor is expired too");
    }

    /// A corrupt floor with a policy depending on it refuses, and says so as a
    /// fault that is not retried. Reporting it as unreadable would tell a caller
    /// to wait for a fault that never clears, when deleting the policy is the
    /// only way out.
    #[test]
    fn a_corrupt_floor_refuses_as_untrusted_while_a_policy_depends_on_it() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.plant(CLOCK_FLOOR_STORAGE_KEY, b"not json".to_vec());

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        // Unwrapped rather than defaulted: the distinction this pins is a
        // refusal as opposed to an error, and a default would pass on either.
        let status = mobile.policy_status(None).unwrap();
        assert!(
            matches!(
                status,
                PolicyStatus::Faulted {
                    fault: PolicyFault::ClockUntrusted
                }
            ),
            "{status:?}"
        );
        assert!(!PolicyFault::ClockUntrusted.is_transient());
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// A floor that cannot be read, as opposed to one that will not parse, may
    /// clear, so with a policy depending on it it refuses as the fault that is
    /// retried.
    #[test]
    fn an_unreadable_floor_refuses_as_retryable_while_a_policy_depends_on_it() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor::new(1, None)).unwrap(),
        );
        storage.fault(CLOCK_FLOOR_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unreadable
            }
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// An unreadable floor must not lock a device with no policy out of ever
    /// installing one. A read that fails is not always transient: a record
    /// whose key alias was invalidated comes back as an error and never
    /// recovers, so refusing on it was the corrupt-record lockout again
    /// through a different door.
    #[test]
    fn an_unreadable_floor_does_not_block_installing_a_first_policy() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let bundle = create_test_bundle_with(&warden, &capped_rules(), now);
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)])
                .expect("serialize wardens"),
        );
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor::new(1, None)).unwrap(),
        );
        storage.fault(CLOCK_FLOOR_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        mobile
            .import_policy(hex::encode(bundle.to_bytes()))
            .expect("no policy depends on the floor, so it must not block the first one");

        // Now one does. A floor that still will not read is the only thing that
        // would say the clock was not wound back, so the policy refuses on it
        // rather than enforcing unchecked, and it is the retried fault.
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unreadable
            }
        ));

        // And once the record reads again, which is what the replacement write
        // is for, the policy is in force. Whether that write repairs a read on
        // a real invalidated key alias is the platform's to answer.
        storage.heal();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// The floor has to advance on an install where nothing is wrong, which is
    /// the only kind the attack is run against. A floor that moved only while
    /// the policy happened to be faulted would never move at all on a working
    /// device, so the record would keep the value it was written with at first
    /// launch and a wound-back clock would sail past it.
    #[test]
    fn the_floor_advances_on_an_install_with_nothing_faulted() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        // Nothing is faulted, so the reload path returns without doing
        // anything; only a floor advanced ahead of that check can move.
        assert!(matches!(
            mobile.policy_status(Some(1_000)).unwrap(),
            PolicyStatus::Active { .. }
        ));

        let written: crate::clock_floor::ClockFloor =
            serde_json::from_slice(&storage.raw(CLOCK_FLOOR_STORAGE_KEY).expect("floor written"))
                .unwrap();
        assert_eq!(
            written.anchor_elapsed_ms,
            Some(1_000),
            "the reading has to reach the floor on a healthy install"
        );

        // An hour of monotonic time later the floor still cannot pass the real
        // clock, which has barely moved, so it advances by less than the
        // quantum and the record is left as it was: no write, and the stored
        // anchor stays put so that hour remains available to credit later.
        mobile.evaluate_policy(a_spend(), Some(3_601_000)).unwrap();
        let later: crate::clock_floor::ClockFloor =
            serde_json::from_slice(&storage.raw(CLOCK_FLOOR_STORAGE_KEY).unwrap()).unwrap();
        assert_eq!(later.anchor_elapsed_ms, written.anchor_elapsed_ms);
        assert_eq!(later.floor_secs, written.floor_secs);
    }

    /// A policy that was in force when it was read must stop being enforced
    /// once it expires, without waiting for anything to re-read it. Nothing
    /// re-reads a policy that is not faulted, so judging validity only where
    /// the record is loaded leaves a running process enforcing retired rules
    /// for as long as it stays up.
    #[test]
    fn an_active_policy_stops_being_enforced_once_it_expires() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));

        // Time moves past the window. Staged through the floor because the real
        // clock cannot be moved under test; the anchor is ahead of the reading
        // passed in, so the observation leaves the planted floor alone.
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor {
                floor_secs: now + 40 * 24 * 3600,
                anchor_elapsed_ms: Some(9_000_000),
            })
            .unwrap(),
        );

        assert!(
            matches!(
                mobile.evaluate_policy(a_spend(), None).unwrap(),
                PolicyDecision::Deny { .. }
            ),
            "an expired bundle must refuse even while memory still holds it as active"
        );
    }

    /// Status and the decision have to agree. Reporting the stored state alone
    /// said `Active`, with the retired limits, about a bundle the decision path
    /// had already started refusing because its window closed while the process
    /// stayed up, which leaves a caller unable to explain the refusals.
    #[test]
    fn status_and_the_decision_agree_once_a_policy_expires() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));

        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor {
                floor_secs: now + 40 * 24 * 3600,
                anchor_elapsed_ms: Some(9_000_000),
            })
            .unwrap(),
        );

        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Faulted {
                    fault: PolicyFault::Expired
                }
            ),
            "status must say why the spend was refused"
        );
        assert!(
            mobile.get_policy_info(None).is_none(),
            "a bundle out of its window is not the policy in force"
        );
    }

    /// With no policy configured the floor guards nothing, so a record that
    /// cannot be read must not refuse. Nothing deletes it, so refusing would
    /// outlive every restart on a device that never had a policy, with no
    /// policy to delete to recover.
    #[test]
    fn an_unreadable_floor_does_not_refuse_when_no_policy_is_configured() {
        let storage = Arc::new(FaultingStorage::default());
        storage.plant(CLOCK_FLOOR_STORAGE_KEY, b"not json".to_vec());

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Allow
        ));

        // The corrupt record was replaced, because nothing depended on it.
        assert!(matches!(
            crate::persistence::load_clock_floor(&(Arc::clone(&storage) as Arc<dyn SecureStorage>)),
            Ok(crate::persistence::ClockFloorRead::Found(_))
        ));

        // And with a policy present a corrupt record refuses, because then it
        // is the only thing saying the clock was not wound back.
        plant_policy(&storage, &capped_rules(), true);
        storage.plant(CLOCK_FLOOR_STORAGE_KEY, b"not json".to_vec());
        let guarded = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            guarded.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    /// A corrupt floor must not leave a device unable to install a policy
    /// ever again. Nothing rewrites the record, so before the fix the way out
    /// of every other fault, deleting the policy, left it in place and every
    /// later import refused on it for good.
    #[test]
    fn a_corrupt_floor_has_a_way_out_through_deleting_the_policy() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let stored = create_test_bundle_with(&warden, &capped_rules(), now);
        storage.plant(
            POLICY_STORAGE_KEY,
            serde_json::to_vec(&stored).expect("serialize policy"),
        );
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(stored.warden_pubkey)])
                .expect("serialize wardens"),
        );
        storage.plant(CLOCK_FLOOR_STORAGE_KEY, b"not json".to_vec());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        // A policy depends on the floor, so it refuses rather than replacing it.
        assert!(matches!(
            mobile.evaluate_policy(a_spend(), None).unwrap(),
            PolicyDecision::Deny { .. }
        ));

        // Deleting the policy is the deliberate act that lets it go; the
        // warden is still trusted, so a replacement installs.
        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &stored.digest())))
            .unwrap();
        let replacement = create_test_bundle_with(&warden, &capped_rules(), now);
        mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .expect("a device with no policy must be able to install one");
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// A read failure the storage reports with `InvalidPolicy` is still a read
    /// failure. That variant is how the floor says its record is corrupt, which
    /// is a fault that is never retried, so taking it at face value from
    /// storage would hold a transient fault for the life of the process.
    #[test]
    fn a_storage_error_is_not_mistaken_for_a_corrupt_floor() {
        let storage = Arc::new(FaultingStorage::default());
        plant_policy(&storage, &capped_rules(), true);
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor::new(1, None)).unwrap(),
        );
        storage.misreport(CLOCK_FLOOR_STORAGE_KEY);

        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let status = mobile.policy_status(None).unwrap();
        assert!(
            matches!(
                status,
                PolicyStatus::Faulted {
                    fault: PolicyFault::Unreadable
                }
            ),
            "{status:?}"
        );
    }

    /// A floor seeded from a clock that was far ahead must have a way out. It is
    /// written from the wall clock before anything can bound it, so it holds a
    /// time in the future that nothing lowers, and every bundle, including one
    /// signed today, reads as expired. Deleting the policy is that way out.
    #[test]
    fn deleting_the_policy_resets_a_floor_seeded_from_a_clock_far_ahead() {
        let now = Utc::now().timestamp() as u64;
        let storage = Arc::new(FaultingStorage::default());
        let warden = k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let bundle = create_test_bundle_with(&warden, &capped_rules(), now);
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(bundle.warden_pubkey)]).unwrap(),
        );
        storage.plant(
            CLOCK_FLOOR_STORAGE_KEY,
            serde_json::to_vec(&crate::clock_floor::ClockFloor::new(
                now + 40 * 24 * 3600,
                None,
            ))
            .unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        // No policy is stored, so the floor is reset without a revocation:
        // with nothing to protect, it guards nothing.
        mobile.delete_policy(None).unwrap();
        mobile
            .import_policy(hex::encode(bundle.to_bytes()))
            .expect("deleting the policy must be a way out of a floor parked ahead");
    }

    // Warden-authorized governance. Every test here is an attempt to remove
    // the policy, or to gain the authority to, without a trusted warden.

    use crate::warden_auth::{unreadable_policy_subject, WardenAction};

    /// The attack this whole change exists for: whoever holds the device
    /// removes the policy and spends without limit.
    #[test]
    fn removing_the_policy_needs_a_trusted_wardens_revocation() {
        let storage = Arc::new(FaultingStorage::default());
        let (_warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        assert!(mobile.delete_policy(None).is_err(), "no revocation");
        let stranger = new_warden();
        assert!(
            mobile
                .delete_policy(Some(revocation(&mobile, &stranger, &bundle.digest())))
                .is_err(),
            "a revocation from a key the device does not trust"
        );
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// Gating removal is worth nothing if the holder can add their own warden
    /// and sign the revocation themselves, so adding one needs a trusted
    /// warden's authorization too.
    #[test]
    fn a_caller_cannot_make_their_own_key_a_trusted_warden() {
        let storage = Arc::new(FaultingStorage::default());
        let (_warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let attacker = new_warden();
        let self_signed = warden_change(
            &mobile,
            &attacker,
            WardenAction::AddWarden,
            &pubkey_of(&attacker),
        );
        assert!(mobile
            .add_trusted_warden(hex::encode(pubkey_of(&attacker)), Some(self_signed))
            .is_err());
        assert!(mobile
            .add_trusted_warden(hex::encode(pubkey_of(&attacker)), None)
            .is_err());

        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(bundle.warden_pubkey)]
        );
        // And so the revocation they would then sign is refused.
        assert!(mobile
            .delete_policy(Some(revocation(&mobile, &attacker, &bundle.digest())))
            .is_err());
    }

    /// The first warden is accepted without an authorization, and only on a
    /// device with no warden and no policy: there is nobody yet to authorize
    /// it and nothing to protect. After that, every addition is authorized.
    #[test]
    fn only_the_first_warden_on_a_fresh_device_needs_no_authorization() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let first = new_warden();
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&first)), None)
            .unwrap();

        let second = new_warden();
        assert!(mobile
            .add_trusted_warden(hex::encode(pubkey_of(&second)), None)
            .is_err());
        let add = warden_change(
            &mobile,
            &first,
            WardenAction::AddWarden,
            &pubkey_of(&second),
        );
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&second)), Some(add))
            .unwrap();
        assert_eq!(mobile.list_trusted_wardens().unwrap().len(), 2);
    }

    /// A device holding a policy that has lost every warden accepts no new
    /// one. Accepting the first one unauthorized there would hand the policy
    /// to whoever asked first; wiping the app data is the way out instead.
    #[test]
    fn a_policy_with_no_wardens_left_takes_no_new_one() {
        let storage = Arc::new(FaultingStorage::default());
        plant_signed_policy(&storage, &capped_rules(), false);
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&Vec::<String>::new()).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let err = mobile
            .add_trusted_warden(hex::encode(pubkey_of(&new_warden())), None)
            .expect_err("no first-warden exception while a policy is stored");
        let KeepMobileError::InvalidPolicy { msg } = err else {
            panic!("expected the locked refusal, got {err:?}");
        };
        assert!(msg.contains("wipe the app data"), "{msg}");
    }

    /// Every authorization is single-use. The case that makes binding to the
    /// warden set insufficient: a key is added, then removed as compromised,
    /// which returns the set to what it was. Replaying the original addition
    /// must not bring the compromised key back.
    #[test]
    fn a_used_authorization_cannot_be_replayed() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let warden = new_warden();
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&warden)), None)
            .unwrap();

        let compromised = new_warden();
        let add = warden_change(
            &mobile,
            &warden,
            WardenAction::AddWarden,
            &pubkey_of(&compromised),
        );
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&compromised)), Some(add.clone()))
            .unwrap();
        let remove = warden_change(
            &mobile,
            &warden,
            WardenAction::RemoveWarden,
            &pubkey_of(&compromised),
        );
        mobile
            .remove_trusted_warden(hex::encode(pubkey_of(&compromised)), remove)
            .unwrap();
        assert_eq!(mobile.list_trusted_wardens().unwrap().len(), 1);

        assert!(
            mobile
                .add_trusted_warden(hex::encode(pubkey_of(&compromised)), Some(add))
                .is_err(),
            "the set is back where it was, and the old addition must still be spent"
        );
        assert_eq!(mobile.list_trusted_wardens().unwrap().len(), 1);
    }

    /// A revocation removes the one policy it names and no other.
    #[test]
    fn a_revocation_removes_only_the_policy_it_names() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, stored) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let other = create_test_bundle_with(&warden, &PolicyRules::default(), stored.created_at);
        assert_ne!(other.digest(), stored.digest());
        assert!(mobile
            .delete_policy(Some(revocation(&mobile, &warden, &other.digest())))
            .is_err());
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &stored.digest())))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
    }

    /// A stored record that will not parse has no digest, so it is named by
    /// the fixed subject for an unreadable policy, and only while it is in
    /// that state. Otherwise it could never be removed at all.
    #[test]
    fn an_unparseable_policy_is_revoked_by_the_unreadable_subject() {
        let storage = Arc::new(FaultingStorage::default());
        let warden = new_warden();
        storage.plant(POLICY_STORAGE_KEY, b"not a policy".to_vec());
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&warden))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        mobile
            .delete_policy(Some(revocation(
                &mobile,
                &warden,
                &unreadable_policy_subject(),
            )))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));

        // Not accepted against a policy that verifies.
        let bundle =
            create_test_bundle_with(&warden, &capped_rules(), Utc::now().timestamp() as u64);
        storage.plant(POLICY_STORAGE_KEY, serde_json::to_vec(&bundle).unwrap());
        assert!(mobile
            .delete_policy(Some(revocation(
                &mobile,
                &warden,
                &unreadable_policy_subject()
            )))
            .is_err());
    }

    /// A warden's signature over the policy cannot be spliced in as a
    /// revocation of it.
    #[test]
    fn a_policy_signature_is_not_a_revocation() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let genuine = revocation(&mobile, &warden, &bundle.digest());
        let mut forged = hex::decode(&genuine).unwrap();
        let sig_at = forged.len() - 64;
        forged[sig_at..].copy_from_slice(&bundle.signature);
        assert!(matches!(
            mobile.delete_policy(Some(hex::encode(forged))),
            Err(KeepMobileError::PolicySignatureInvalid)
        ));
    }

    /// Removing a warden is authorized too, and the device stays at the old
    /// epoch when it is refused.
    #[test]
    fn removing_a_warden_needs_authorization() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let warden = new_warden();
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&warden)), None)
            .unwrap();
        let epoch = mobile.warden_governance().unwrap().epoch;

        let stranger = new_warden();
        let bad = warden_change(
            &mobile,
            &stranger,
            WardenAction::RemoveWarden,
            &pubkey_of(&warden),
        );
        assert!(mobile
            .remove_trusted_warden(hex::encode(pubkey_of(&warden)), bad)
            .is_err());
        assert_eq!(mobile.warden_governance().unwrap().epoch, epoch);
        assert_eq!(mobile.list_trusted_wardens().unwrap().len(), 1);
    }

    /// A wardens record written before the epoch existed is a bare list, and
    /// reads as epoch 0 with its wardens intact, so an existing install keeps
    /// its trust and can be governed from there.
    #[test]
    fn a_wardens_record_from_before_the_epoch_reads_as_epoch_zero() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert_eq!(mobile.warden_governance().unwrap().epoch, 0);
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));

        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &bundle.digest())))
            .unwrap();
        assert_eq!(mobile.warden_governance().unwrap().epoch, 1);
        let raw: serde_json::Value =
            serde_json::from_slice(&storage.raw(TRUSTED_WARDENS_KEY).unwrap()).unwrap();
        assert_eq!(raw["epoch"], 1, "rewritten in the current format");
        assert_eq!(
            raw["wardens"],
            serde_json::json!([hex::encode(pubkey_of(&warden))]),
            "the wardens carried over"
        );
    }

    /// The last warden cannot be removed while a policy is stored, since
    /// nothing would be left able to revoke it and the only way out would be a
    /// wipe that loses the share. Once the policy is revoked it can.
    #[test]
    fn the_last_warden_stays_while_a_policy_is_stored() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let me = pubkey_of(&warden);

        let remove = warden_change(&mobile, &warden, WardenAction::RemoveWarden, &me);
        let err = mobile
            .remove_trusted_warden(hex::encode(me), remove)
            .expect_err("emptying the wardens under a policy must be refused");
        let KeepMobileError::InvalidPolicy { msg } = err else {
            panic!("expected the removal to be refused, got {err:?}");
        };
        assert!(msg.contains("revoke the policy first"), "{msg}");
        assert_eq!(mobile.warden_governance().unwrap().epoch, 0);
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));

        mobile
            .delete_policy(Some(revocation(&mobile, &warden, &bundle.digest())))
            .unwrap();
        let remove = warden_change(&mobile, &warden, WardenAction::RemoveWarden, &me);
        mobile
            .remove_trusted_warden(hex::encode(me), remove)
            .unwrap();
        assert!(mobile.list_trusted_wardens().unwrap().is_empty());
    }

    /// An authorization names the device it was signed for. Two co-signers
    /// holding the same bundle at the same epoch are exactly where one would
    /// otherwise replay on the other.
    #[test]
    fn an_authorization_for_one_device_does_not_apply_to_another() {
        let storage_a = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage_a, &capped_rules(), true);
        let storage_b = Arc::new(FaultingStorage::default());
        storage_b.plant(
            POLICY_STORAGE_KEY,
            storage_a.raw(POLICY_STORAGE_KEY).unwrap(),
        );
        storage_b.plant(
            TRUSTED_WARDENS_KEY,
            storage_a.raw(TRUSTED_WARDENS_KEY).unwrap(),
        );
        let a = KeepMobile::new(Arc::clone(&storage_a) as Arc<dyn SecureStorage>).unwrap();
        let b = KeepMobile::new(Arc::clone(&storage_b) as Arc<dyn SecureStorage>).unwrap();
        assert_eq!(
            a.warden_governance().unwrap().epoch,
            b.warden_governance().unwrap().epoch
        );
        assert_ne!(
            a.warden_governance().unwrap().device_id,
            b.warden_governance().unwrap().device_id
        );

        let for_a = revocation(&a, &warden, &bundle.digest());
        assert!(b.delete_policy(Some(for_a.clone())).is_err());
        assert!(matches!(
            b.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
        a.delete_policy(Some(for_a)).unwrap();
    }

    /// Installing a policy spends any authorization outstanding, so a
    /// revocation held back while a read was failing cannot later remove the
    /// policy that replaced the one it was meant for.
    #[test]
    fn an_install_spends_a_held_revocation() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let held = revocation(&mobile, &warden, &unreadable_policy_subject());
        let epoch = mobile.warden_governance().unwrap().epoch;

        let renewal = create_test_bundle_with(&warden, &capped_rules(), bundle.created_at + 1);
        mobile
            .import_policy(hex::encode(renewal.to_bytes()))
            .unwrap();
        assert_eq!(mobile.warden_governance().unwrap().epoch, epoch + 1);

        storage.fault(POLICY_STORAGE_KEY);
        assert!(mobile.delete_policy(Some(held)).is_err());
        storage.heal();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// A key that is not a curve point is refused before it is trusted, since
    /// it could never sign and taking the first-warden slot with it would
    /// leave the device ungovernable.
    #[test]
    fn a_warden_key_that_is_not_a_point_is_refused() {
        let storage = Arc::new(FaultingStorage::default());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        // x = 0 is not on secp256k1: 0^3 + 7 = 7 is not a square mod p.
        assert!(mobile
            .add_trusted_warden(hex::encode([0u8; 32]), None)
            .is_err());
        assert!(mobile.list_trusted_wardens().unwrap().is_empty());
        assert_eq!(mobile.warden_governance().unwrap().epoch, 0);
    }

    /// A wardens record from before the device id gets one the first time it
    /// is governed, and keeps it, so a warden can read it once and sign.
    #[test]
    fn a_device_id_is_generated_once_and_kept() {
        let storage = Arc::new(FaultingStorage::default());
        plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let first = mobile.warden_governance().unwrap();
        assert_eq!(first.device_id.len(), 64);
        let again = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>)
            .unwrap()
            .warden_governance()
            .unwrap();
        assert_eq!(first, again);
        let raw: serde_json::Value =
            serde_json::from_slice(&storage.raw(TRUSTED_WARDENS_KEY).unwrap()).unwrap();
        assert_eq!(raw["device"], first.device_id);
    }

    /// A record that parses but fails verification, here one whose rules were
    /// edited, has a digest no warden knows, so it is named by the fixed
    /// subject. Requiring its digest left a device holding one refusing every
    /// spend until it was wiped, since an install is refused over it too.
    #[test]
    fn an_edited_policy_is_revoked_by_the_unattributable_subject() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let text = String::from_utf8(storage.raw(POLICY_STORAGE_KEY).unwrap()).unwrap();
        let edited = text.replace("100000", "900000");
        assert_ne!(edited, text);
        storage.plant(POLICY_STORAGE_KEY, edited.into_bytes());
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));

        assert!(mobile
            .delete_policy(Some(revocation(&mobile, &warden, &bundle.digest())))
            .is_err());
        mobile
            .delete_policy(Some(revocation(
                &mobile,
                &warden,
                &unreadable_policy_subject(),
            )))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
    }

    /// The stored policy's signer cannot be removed while that policy is in
    /// place, so a lost wardens record rebuilt from the signer never trusts a
    /// warden that was taken out. Installing a replacement signed by another
    /// warden first lets the removal through.
    #[test]
    fn the_stored_policy_signer_stays_until_the_policy_is_replaced() {
        let storage = Arc::new(FaultingStorage::default());
        let (signer, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let other = new_warden();
        let add = warden_change(
            &mobile,
            &signer,
            WardenAction::AddWarden,
            &pubkey_of(&other),
        );
        mobile
            .add_trusted_warden(hex::encode(pubkey_of(&other)), Some(add))
            .unwrap();

        let remove = warden_change(
            &mobile,
            &other,
            WardenAction::RemoveWarden,
            &pubkey_of(&signer),
        );
        assert!(mobile
            .remove_trusted_warden(hex::encode(pubkey_of(&signer)), remove)
            .is_err());

        let replacement = create_test_bundle_with(&other, &capped_rules(), bundle.created_at + 1);
        mobile
            .import_policy(hex::encode(replacement.to_bytes()))
            .unwrap();
        let remove = warden_change(
            &mobile,
            &other,
            WardenAction::RemoveWarden,
            &pubkey_of(&signer),
        );
        mobile
            .remove_trusted_warden(hex::encode(pubkey_of(&signer)), remove)
            .unwrap();
        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(pubkey_of(&other))]
        );
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// A policy whose signer is no longer trusted, as on a device that removed
    /// it before the signer had to stay, does not verify, so the warden left is
    /// not expected to know its digest; it revokes it by the fixed subject.
    #[test]
    fn a_policy_whose_signer_was_removed_is_revoked_by_the_remaining_warden() {
        let storage = Arc::new(FaultingStorage::default());
        plant_signed_policy(&storage, &capped_rules(), false);
        let other = new_warden();
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&other))]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Faulted {
                fault: PolicyFault::Unverified
            }
        ));

        mobile
            .delete_policy(Some(revocation(
                &mobile,
                &other,
                &unreadable_policy_subject(),
            )))
            .unwrap();
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
    }

    /// The fixed subject is not accepted for a policy that verifies: that one
    /// is named by its digest, which the warden who signed it knows.
    #[test]
    fn a_verified_policy_is_not_revoked_by_the_unattributable_subject() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, _bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        assert!(mobile
            .delete_policy(Some(revocation(
                &mobile,
                &warden,
                &unreadable_policy_subject(),
            )))
            .is_err());
        assert!(matches!(
            mobile.policy_status(None).unwrap(),
            PolicyStatus::Active { .. }
        ));
    }

    /// A delete that fails leaves a faulted policy faulted, not cleared.
    #[test]
    fn a_delete_that_fails_leaves_a_faulted_policy_refusing() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, _bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        storage.fault(POLICY_STORAGE_KEY);
        storage.fault_delete(POLICY_STORAGE_KEY);
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let revoke = revocation(&mobile, &warden, &unreadable_policy_subject());
        assert!(mobile.delete_policy(Some(revoke)).is_err());
        assert!(
            matches!(
                mobile.policy_status(None).unwrap(),
                PolicyStatus::Faulted { .. }
            ),
            "a failed delete must not leave memory reading as no policy"
        );
    }

    /// With nothing stored, deleting clears a policy memory still holds, such
    /// as one another instance on the same storage revoked, rather than
    /// reporting success while still enforcing it.
    #[test]
    fn deleting_with_nothing_stored_clears_memory() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), true);
        let a = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        let b = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();
        a.delete_policy(Some(revocation(&a, &warden, &bundle.digest())))
            .unwrap();
        b.delete_policy(None).unwrap();
        assert!(matches!(
            b.policy_status(None).unwrap(),
            PolicyStatus::NotConfigured
        ));
    }

    /// A key that is not a curve point, stored before keys were checked, can
    /// still be removed, and does not count as a warden able to revoke the
    /// policy when deciding whether the last one is being removed.
    #[test]
    fn a_stored_key_that_cannot_sign_is_removable_and_does_not_count() {
        let storage = Arc::new(FaultingStorage::default());
        let (warden, bundle) = plant_signed_policy(&storage, &capped_rules(), false);
        let dead = [0u8; 32];
        storage.plant(
            TRUSTED_WARDENS_KEY,
            serde_json::to_vec(&vec![hex::encode(pubkey_of(&warden)), hex::encode(dead)]).unwrap(),
        );
        let mobile = KeepMobile::new(Arc::clone(&storage) as Arc<dyn SecureStorage>).unwrap();

        let remove = warden_change(
            &mobile,
            &warden,
            WardenAction::RemoveWarden,
            &pubkey_of(&warden),
        );
        assert!(mobile
            .remove_trusted_warden(hex::encode(pubkey_of(&warden)), remove)
            .is_err());

        let remove = warden_change(&mobile, &warden, WardenAction::RemoveWarden, &dead);
        mobile
            .remove_trusted_warden(hex::encode(dead), remove)
            .unwrap();
        assert_eq!(
            mobile.list_trusted_wardens().unwrap(),
            vec![hex::encode(bundle.warden_pubkey)]
        );
    }
}
