// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::nip55::Nip55RequestType;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const HIGH_FREQUENCY_THRESHOLD: u32 = 10;
const NEW_APP_THRESHOLD_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_TRACKED_PACKAGES: usize = 500;

const HOURLY_LIMIT: u32 = 100;
const DAILY_LIMIT: u32 = 500;
const UNUSUAL_ACTIVITY_THRESHOLD: u32 = 50;
const UNUSUAL_ACTIVITY_WINDOW_MS: u64 = 60_000;
const COOLING_OFF_PERIOD_MS: u64 = 15 * 60 * 1000;
const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const RISK_ESCALATION_THRESHOLD: u32 = 40;
/// The `Basic` policy's auto-approval ceiling: the `SigningAuthLevel::None` band
/// (`assess_signing_risk` returns `None` below a score of 20). `Basic` therefore
/// auto-approves only requests the risk model rates as needing no extra auth,
/// making it a strict subset of `Auto` (which auto-approves up to
/// `RISK_ESCALATION_THRESHOLD`).
const BASIC_RISK_THRESHOLD: u32 = 20;

const SENSITIVE_KINDS: &[u32] = &[
    0,     // Metadata (profile)
    3,     // Contacts (follow list)
    4,     // Encrypted Direct Message (NIP-04)
    13,    // Seal (NIP-59)
    14,    // Direct Message (NIP-17)
    1059,  // Gift Wrap (NIP-59)
    1984,  // Report
    10000, // Mute List
    10002, // Relay List Metadata
    10003, // Bookmark List
    10004, // Search Relay List
    10006, // Blocked Relays List
    10050, // DM Relay List
    22242, // Client Authentication (NIP-42)
    27235, // HTTP Auth (NIP-98)
];

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SigningAuthLevel {
    None,
    Pin,
    Biometric,
    Explicit,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SigningRiskFactor {
    SensitiveEventKind,
    SensitiveOperation,
    UnusualTime,
    HighFrequency,
    NewApp,
    UnknownAge,
    FirstKind,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SigningRiskAssessment {
    pub score: u32,
    pub factors: Vec<SigningRiskFactor>,
    pub required_auth: SigningAuthLevel,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SigningRequestContext {
    pub operation: Nip55RequestType,
    pub package_name: String,
    pub event_kind: Option<u32>,
    pub has_signed_kind_before: bool,
    pub app_age_ms: Option<u64>,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum AutoSignDecision {
    Allowed {
        hourly_count: u32,
        daily_count: u32,
        recent_count: u32,
        hourly_limit: u32,
        daily_limit: u32,
    },
    HourlyLimitExceeded,
    DailyLimitExceeded,
    UnusualActivity,
    CoolingOff {
        until_ms: u64,
    },
    /// The usage counters could not be durably recorded, so this request cannot
    /// be counted toward the hourly and daily ceilings. Auto-signing is refused
    /// rather than allowed: continuing would let every subsequent request reuse
    /// the same un-incremented window and bypass the limits entirely. Appended
    /// last so the existing variants keep their wire ordinals.
    StorageUnavailable,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SignPolicyEvaluation {
    AutoApprove,
    FallToUi,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    Manual,
    Auto,
}

/// The sign-policy SELECTION the user chose, distinct from the 2-value
/// evaluation [`PolicyMode`]. Ordinals match keep-android's `SignPolicy`
/// (Manual=0, Basic=1, Auto=2), so migrating the client's stored value is a
/// pure read-through.
///
/// `Basic` and `Auto` get distinct runtime behavior via
/// [`evaluate_sign_policy_selection`], where `Basic` is a strictly stricter auto
/// tier than `Auto` (#716). The legacy [`policy_mode`] bridge still collapses both
/// onto [`PolicyMode::Auto`] for callers on the 2-value [`evaluate_sign_policy`]
/// path; those callers see the previous behavior until they migrate to the
/// selection-aware evaluator.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPolicySelection {
    Manual,
    Basic,
    Auto,
}

impl SignPolicySelection {
    fn to_ordinal(self) -> u8 {
        match self {
            SignPolicySelection::Manual => 0,
            SignPolicySelection::Basic => 1,
            SignPolicySelection::Auto => 2,
        }
    }

    /// Parse an ordinal, defaulting to the safest mode (`Manual`) on any
    /// unknown/garbage value, matching keep-android's `fromOrdinal`.
    fn from_ordinal(ordinal: u8) -> Self {
        match ordinal {
            1 => SignPolicySelection::Basic,
            2 => SignPolicySelection::Auto,
            _ => SignPolicySelection::Manual,
        }
    }

    /// Map the selection onto the legacy 2-value evaluation mode. `Basic` and
    /// `Auto` both map to `Auto` here; the selection-aware
    /// [`evaluate_sign_policy_selection`] is what distinguishes them at runtime.
    pub fn policy_mode(self) -> PolicyMode {
        match self {
            SignPolicySelection::Manual => PolicyMode::Manual,
            SignPolicySelection::Basic | SignPolicySelection::Auto => PolicyMode::Auto,
        }
    }
}

/// Outcome of reading a usage window: a live window, a legitimately fresh one,
/// or a read that could not be trusted. Internal to the limiter.
enum WindowRead {
    Active(UsageWindow),
    Fresh,
    Unavailable,
}

impl WindowRead {
    /// Count for reporting only, where an unreadable window shows as zero. The
    /// authorization path must not use this: it has to distinguish "no usage"
    /// from "unknown usage" and refuse on the latter.
    fn display_count(&self) -> u32 {
        match self {
            WindowRead::Active(w) => w.count,
            WindowRead::Fresh | WindowRead::Unavailable => 0,
        }
    }
}

/// Outcome of a rate-limiter storage read.
///
/// The distinction between `Absent` and `Unavailable` is load-bearing. A missing
/// key legitimately means "no usage recorded yet", so the window starts fresh. A
/// read that failed means nothing is known, and starting fresh there would reset
/// the count on every request and make the hourly and daily ceilings unreachable.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum StorageRead {
    /// The key holds this value.
    Found { value: String },
    /// The key is genuinely not present.
    Absent,
    /// The value could not be read or decoded. Callers must fail closed.
    Unavailable,
}

/// Persistence for the sign-policy selection (global + per-app override). A
/// simple string key/value store; the Android side backs it with its encrypted
/// sign-policy prefs.
///
/// `save` and `remove` report whether the write durably persisted. The return
/// must be the platform's own durable-write result, NOT a "did not throw" flag:
/// wrapping the call and reporting that no exception escaped is the same as
/// reporting nothing, and reintroduces the defect this signal exists to remove.
///
/// `false` means INDETERMINATE, not "the old value survived". A store that
/// caches in memory ahead of its backing file will serve the value a failed
/// write left behind, so after `false` either value may be the one in force, and
/// the selection is read straight from here on every signing decision. A caller
/// must therefore treat `false` as "I do not know what is stored" and repair it
/// by re-asserting the stricter of the old and new selections (or `Manual`),
/// rather than assuming the change simply did not happen.
#[uniffi::export(with_foreign)]
pub trait SignPolicySelectionStorage: Send + Sync {
    fn load(&self, key: String) -> Option<String>;
    /// Persist `value` under `key`. Returns whether it durably persisted.
    fn save(&self, key: String, value: String) -> bool;
    /// Delete `key`. Returns whether the deletion reached the durable store.
    ///
    /// A key that is genuinely absent from the durable store is a success. A
    /// lookup that could not determine absence is NOT: an implementation whose
    /// key derivation or index is unavailable must return `false` rather than
    /// treat "I cannot see it" as "it is gone", or a live entry stays on disk
    /// and becomes enforceable again once lookup recovers. Do not short-circuit
    /// on a cached `contains`.
    fn remove(&self, key: String) -> bool;
}

const GLOBAL_SIGN_POLICY_KEY: &str = "global_sign_policy";

fn app_override_key(package: &str) -> String {
    format!("sign_policy_override:{package}")
}

/// Core-owned store for the sign-policy selection, so the selection state and
/// its override -> global -> Manual precedence live in one place rather than
/// being reimplemented in each client (#716). Feeds the evaluation via
/// [`SignPolicyStore::effective_policy`] + [`evaluate_sign_policy_selection`].
#[derive(uniffi::Object)]
pub struct SignPolicyStore {
    storage: Arc<dyn SignPolicySelectionStorage>,
}

#[uniffi::export]
impl SignPolicyStore {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SignPolicySelectionStorage>) -> Self {
        Self { storage }
    }

    /// The global sign-policy selection, defaulting to `Manual` when unset or
    /// unparseable (fail safe).
    pub fn global_policy(&self) -> SignPolicySelection {
        self.storage
            .load(GLOBAL_SIGN_POLICY_KEY.to_string())
            .and_then(|s| s.parse::<u8>().ok())
            .map(SignPolicySelection::from_ordinal)
            .unwrap_or(SignPolicySelection::Manual)
    }

    /// Persist the global sign-policy selection. `true` means the global key
    /// reached the durable store, not that this selection now governs any given
    /// package: a per-app override still wins (see [`Self::effective_policy`]).
    ///
    /// `false` is indeterminate, so the caller must repair rather than assume
    /// the old value held; see [`SignPolicySelectionStorage`].
    pub fn set_global_policy(&self, policy: SignPolicySelection) -> bool {
        self.storage.save(
            GLOBAL_SIGN_POLICY_KEY.to_string(),
            policy.to_ordinal().to_string(),
        )
    }

    /// The per-app override, or `None` if the app follows the global policy.
    pub fn app_override(&self, package: String) -> Option<SignPolicySelection> {
        self.storage
            .load(app_override_key(&package))
            .and_then(|s| s.parse::<u8>().ok())
            .map(SignPolicySelection::from_ordinal)
    }

    /// Set (`Some`) or clear (`None`) the per-app override. Returns whether the
    /// write persisted.
    ///
    /// A failed clear matters most: an override is typically stricter than the
    /// global policy, so a caller that treats an unconfirmed clear as done can
    /// drop the record that the override still exists and leave it in force with
    /// nothing tracking it. Callers must keep their own index until this reports
    /// `true`, and must re-attempt on `false` rather than assume the override
    /// was left untouched, since `false` does not say which value is stored.
    pub fn set_app_override(&self, package: String, policy: Option<SignPolicySelection>) -> bool {
        match policy {
            Some(p) => self
                .storage
                .save(app_override_key(&package), p.to_ordinal().to_string()),
            None => self.storage.remove(app_override_key(&package)),
        }
    }

    /// Resolve the effective selection for a package: per-app override, else the
    /// global policy, else `Manual`. Mirrors keep-android's precedence.
    pub fn effective_policy(&self, package: String) -> SignPolicySelection {
        self.app_override(package)
            .unwrap_or_else(|| self.global_policy())
    }

    /// Legacy bridge to the 2-value [`PolicyMode`], for callers still on the
    /// 2-value [`evaluate_sign_policy`]. It collapses `Basic` onto
    /// [`PolicyMode::Auto`], which silently re-disables the stricter `Basic` tier
    /// -- do NOT route the decision path through it. Use [`Self::effective_policy`]
    /// with [`evaluate_sign_policy_selection`] instead.
    pub fn effective_policy_mode(&self, package: String) -> PolicyMode {
        self.effective_policy(package).policy_mode()
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct UsageStats {
    pub hourly_count: u32,
    pub daily_count: u32,
    pub hourly_limit: u32,
    pub daily_limit: u32,
}

#[uniffi::export]
pub fn is_sensitive_kind(kind: u32) -> bool {
    SENSITIVE_KINDS.contains(&kind) || (30000..=39999).contains(&kind)
}

#[uniffi::export]
pub fn sensitive_kind_warning(kind: u32) -> Option<String> {
    let warning = match kind {
        0 => "Modifying profile metadata can affect your identity across all Nostr clients",
        3 => "Modifying contacts can affect who you follow across all Nostr clients",
        4 => "Encrypted direct messages contain private communications",
        13 => "Sealed events contain encrypted private communications",
        14 => "Direct messages contain private communications",
        1059 => "Gift wrapped events may contain private communications",
        1984 => "Reports can affect reputation and content moderation",
        10000 => "Modifying mute list can affect your experience across all Nostr clients",
        10002 => "Modifying relay list can affect your connectivity across all Nostr clients",
        10003 => "Modifying bookmarks can affect your saved content across all Nostr clients",
        10004 => "Modifying search relay list can affect your search experience",
        10006 => "Modifying blocked relays can affect your connectivity",
        10050 => {
            "Modifying DM relay list can affect your private messaging across all Nostr clients"
        }
        22242 => "Client authentication can grant relay access permissions",
        27235 => "HTTP authentication can authorize external service access",
        k if (30000..=39999).contains(&k) => {
            "Replaceable events can be overwritten and may contain sensitive data"
        }
        _ => return None,
    };
    Some(warning.to_string())
}

#[uniffi::export]
pub fn assess_signing_risk(
    ctx: SigningRequestContext,
    recent_request_count: u32,
    current_hour: u32,
) -> SigningRiskAssessment {
    let mut factors = Vec::new();

    let current_hour = current_hour.clamp(0, 23);

    match ctx.operation {
        Nip55RequestType::Nip04Encrypt
        | Nip55RequestType::Nip44Encrypt
        | Nip55RequestType::Nip04Decrypt
        | Nip55RequestType::Nip44Decrypt
        | Nip55RequestType::Nip44V3Encrypt
        | Nip55RequestType::Nip44V3Decrypt
        | Nip55RequestType::DecryptZapEvent => {
            factors.push(SigningRiskFactor::SensitiveOperation);
        }
        Nip55RequestType::GetPublicKey | Nip55RequestType::SignEvent => {}
    }

    if let Some(kind) = ctx.event_kind {
        if is_sensitive_kind(kind) {
            factors.push(SigningRiskFactor::SensitiveEventKind);
        }
        if !ctx.has_signed_kind_before {
            factors.push(SigningRiskFactor::FirstKind);
        }
    }

    if recent_request_count > HIGH_FREQUENCY_THRESHOLD {
        factors.push(SigningRiskFactor::HighFrequency);
    }

    if !(6..23).contains(&current_hour) {
        factors.push(SigningRiskFactor::UnusualTime);
    }

    match ctx.app_age_ms {
        None => factors.push(SigningRiskFactor::UnknownAge),
        Some(age) if age < NEW_APP_THRESHOLD_MS => factors.push(SigningRiskFactor::NewApp),
        _ => {}
    }

    let score: u32 = factors
        .iter()
        .map(|f| match f {
            SigningRiskFactor::SensitiveEventKind => 40,
            SigningRiskFactor::SensitiveOperation => 40,
            SigningRiskFactor::UnusualTime => 10,
            SigningRiskFactor::HighFrequency => 20,
            SigningRiskFactor::NewApp => 15,
            SigningRiskFactor::UnknownAge => 5,
            SigningRiskFactor::FirstKind => 15,
        })
        .sum::<u32>()
        .min(100);

    let required_auth = if score >= 60 {
        SigningAuthLevel::Explicit
    } else if score >= 40 {
        SigningAuthLevel::Biometric
    } else if score >= 20 {
        SigningAuthLevel::Pin
    } else {
        SigningAuthLevel::None
    };

    SigningRiskAssessment {
        score,
        factors,
        required_auth,
    }
}

const HOURLY_KEY_PREFIX: &str = "hourly_";
const DAILY_KEY_PREFIX: &str = "daily_";
const COOLED_OFF_KEY_PREFIX: &str = "cooled_off_";
const COOLED_OFF_ELAPSED_KEY_PREFIX: &str = "cooled_off_elapsed_";

/// Build a storage key. The `:` separator cannot appear in an Android package
/// name (segments are `[a-zA-Z0-9_]`), so prefixes never collide with each other
/// regardless of the package name.
fn key(prefix: &str, package_name: &str) -> String {
    format!("{prefix}:{package_name}")
}

struct UsageWindow {
    count: u32,
    /// Window start on the monotonic clock (Android `elapsedRealtime`).
    start_elapsed: u64,
}

/// Persistence backend for the per-package velocity counters and cooling-off
/// state, so they survive a keep restart (a reboot, OS-kill, or upgrade). A
/// simple string key/value store; the Android side backs it with the encrypted
/// `nip55_auto_signing` prefs.
#[uniffi::export(with_foreign)]
pub trait SigningRateLimiterStorage: Send + Sync {
    /// Read `key`. `Absent` and `Unavailable` must not be conflated: a counter
    /// that could not be read is not the same as a package with no history, and
    /// treating the former as the latter restarts the window at zero on every
    /// request, which removes the ceiling just as effectively as a lost write.
    fn load(&self, key: String) -> StorageRead;
    /// Persist `value` under `key`. Returns whether it durably persisted.
    ///
    /// As with [`SignPolicySelectionStorage`], the return must be the platform's
    /// own durable-write result, not a "did not throw" flag. These counters are
    /// not telemetry: [`SigningRateLimiter::check_and_record`] gates auto-signing
    /// on them, so a write that silently vanishes means the request is never
    /// counted, the hourly and daily ceilings never accumulate toward their
    /// limits, and a cooling-off penalty is dropped. That widens the sustained
    /// auto-approval rate rather than losing a statistic.
    fn save(&self, key: String, value: String) -> bool;
    fn remove(&self, key: String) -> bool;
    fn clear(&self) -> bool;
}

/// Per-package velocity limiter for opt-in auto-signing. Hourly and daily
/// counters and the cooling-off state are persisted via [`SigningRateLimiterStorage`]
/// so they cannot be reset by restarting keep; the short unusual-activity window
/// is kept in memory. Windows are tracked on the monotonic clock and persisted
/// with a wall-clock anchor, so they survive a reboot (which resets the monotonic
/// clock) without trusting a manipulable wall clock for liveness.
#[derive(uniffi::Object)]
pub struct SigningRateLimiter {
    storage: Arc<dyn SigningRateLimiterStorage>,
    recent: Mutex<HashMap<String, UsageWindow>>,
    /// Serializes the storage read-modify-write critical sections so concurrent
    /// calls for the same package cannot lose an increment. Always acquired
    /// before `recent` to keep a consistent lock order.
    guard: Mutex<()>,
}

#[uniffi::export]
impl SigningRateLimiter {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SigningRateLimiterStorage>) -> Self {
        Self {
            storage,
            recent: Mutex::new(HashMap::new()),
            guard: Mutex::new(()),
        }
    }

    /// Record one auto-sign attempt for `package_name` and decide whether it is
    /// allowed. `now_elapsed_ms` is the monotonic clock; `now_wall_ms` is wall
    /// time. Exceeding any limit starts a 15-minute cooling-off.
    pub fn check_and_record(
        &self,
        package_name: String,
        now_elapsed_ms: u64,
        now_wall_ms: u64,
    ) -> AutoSignDecision {
        let _guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());

        // Every read below fails closed. Unknown prior usage is not "no prior
        // usage": treating it as none would restart the window on each request
        // and make the ceilings unreachable, which is the same bypass a lost
        // write produces.
        let Some(cooled) = self.cooled_off_state(&package_name, now_elapsed_ms, now_wall_ms) else {
            return AutoSignDecision::StorageUnavailable;
        };
        if cooled.active() {
            return AutoSignDecision::CoolingOff {
                until_ms: cooled.until_wall_ms(now_elapsed_ms, now_wall_ms),
            };
        }

        // Compute would-be counts first; a denied request must not increment the
        // persisted counter, so the windows are only saved once every limit
        // passes.
        let Some(hourly) = self.next_window(
            HOURLY_KEY_PREFIX,
            &package_name,
            HOUR_MS,
            now_elapsed_ms,
            now_wall_ms,
        ) else {
            return AutoSignDecision::StorageUnavailable;
        };
        if hourly.count > HOURLY_LIMIT {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::HourlyLimitExceeded;
        }

        let Some(daily) = self.next_window(
            DAILY_KEY_PREFIX,
            &package_name,
            DAY_MS,
            now_elapsed_ms,
            now_wall_ms,
        ) else {
            return AutoSignDecision::StorageUnavailable;
        };
        if daily.count > DAILY_LIMIT {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::DailyLimitExceeded;
        }

        let recent = self.bump_recent(&package_name, now_elapsed_ms);
        if recent > UNUSUAL_ACTIVITY_THRESHOLD {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::UnusualActivity;
        }

        // Both counters must land before this request can be called allowed. If
        // either write is lost, the window stays un-incremented and every later
        // request reads the same count, so the hourly and daily ceilings would
        // never be reached and auto-signing would be effectively unlimited.
        // Refusing costs a prompt; continuing removes the limit.
        let hourly_saved = self.save_window(HOURLY_KEY_PREFIX, &package_name, &hourly, now_wall_ms);
        let daily_saved = self.save_window(DAILY_KEY_PREFIX, &package_name, &daily, now_wall_ms);
        if !hourly_saved || !daily_saved {
            return AutoSignDecision::StorageUnavailable;
        }

        AutoSignDecision::Allowed {
            hourly_count: hourly.count,
            daily_count: daily.count,
            recent_count: recent,
            hourly_limit: HOURLY_LIMIT,
            daily_limit: DAILY_LIMIT,
        }
    }

    pub fn clear_cooling_off(&self, package_name: String) {
        let _guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        self.storage
            .remove(key(COOLED_OFF_KEY_PREFIX, &package_name));
        self.storage
            .remove(key(COOLED_OFF_ELAPSED_KEY_PREFIX, &package_name));
        // Also drop the velocity counters; leaving an over-limit counter in
        // place would immediately re-trip cooling-off on the next request.
        self.storage.remove(key(HOURLY_KEY_PREFIX, &package_name));
        self.storage.remove(key(DAILY_KEY_PREFIX, &package_name));
    }

    pub fn clear_all(&self) {
        let _guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        self.storage.clear();
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn get_usage_stats(
        &self,
        package_name: String,
        now_elapsed_ms: u64,
        now_wall_ms: u64,
    ) -> UsageStats {
        let _guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        let hourly_count = self
            .read_window(
                HOURLY_KEY_PREFIX,
                &package_name,
                HOUR_MS,
                now_elapsed_ms,
                now_wall_ms,
            )
            .display_count();
        let daily_count = self
            .read_window(
                DAILY_KEY_PREFIX,
                &package_name,
                DAY_MS,
                now_elapsed_ms,
                now_wall_ms,
            )
            .display_count();
        UsageStats {
            hourly_count,
            daily_count,
            hourly_limit: HOURLY_LIMIT,
            daily_limit: DAILY_LIMIT,
        }
    }
}

impl SigningRateLimiter {
    /// Load an unexpired persisted window, reconstructing the monotonic start
    /// across a reboot from the wall-clock anchor. Returns `None` when absent,
    /// unparseable, or expired.
    fn read_window(
        &self,
        prefix: &str,
        package_name: &str,
        window_ms: u64,
        now_elapsed_ms: u64,
        now_wall_ms: u64,
    ) -> WindowRead {
        let raw = match self.storage.load(key(prefix, package_name)) {
            StorageRead::Found { value } => value,
            // No history yet: a genuinely fresh window, not a fault.
            StorageRead::Absent => return WindowRead::Fresh,
            StorageRead::Unavailable => return WindowRead::Unavailable,
        };
        // Stored but undecodable is a fault, not a fresh window: treating corrupt
        // data as "no usage" would reset the counter on every request.
        let Some(window) = parse_window(&raw, now_elapsed_ms, now_wall_ms) else {
            return WindowRead::Unavailable;
        };
        let active = now_elapsed_ms
            .checked_sub(window.start_elapsed)
            .is_some_and(|elapsed| elapsed < window_ms);
        if active {
            WindowRead::Active(window)
        } else {
            WindowRead::Fresh
        }
    }

    /// Compute the window the next increment would produce, without persisting
    /// it. The caller saves it via [`save_window`] only if the request is
    /// allowed, so a denied request never bumps the stored counter.
    fn next_window(
        &self,
        prefix: &str,
        package_name: &str,
        window_ms: u64,
        now_elapsed_ms: u64,
        now_wall_ms: u64,
    ) -> Option<UsageWindow> {
        match self.read_window(prefix, package_name, window_ms, now_elapsed_ms, now_wall_ms) {
            WindowRead::Active(mut w) => {
                w.count = w.count.saturating_add(1);
                Some(w)
            }
            WindowRead::Fresh => Some(UsageWindow {
                count: 1,
                start_elapsed: now_elapsed_ms,
            }),
            // Unknown prior usage: the caller must refuse rather than assume none.
            WindowRead::Unavailable => None,
        }
    }

    /// Returns whether the counter durably persisted. A `false` here means this
    /// request was not counted, so the caller must not report it as allowed.
    fn save_window(
        &self,
        prefix: &str,
        package_name: &str,
        window: &UsageWindow,
        now_wall_ms: u64,
    ) -> bool {
        self.storage.save(
            key(prefix, package_name),
            serialize_window(window, now_wall_ms),
        )
    }

    /// Increment the in-memory unusual-activity window (60s); not persisted.
    fn bump_recent(&self, package_name: &str, now_elapsed_ms: u64) -> u32 {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        recent.retain(|_, w| {
            now_elapsed_ms
                .checked_sub(w.start_elapsed)
                .is_some_and(|e| e < UNUSUAL_ACTIVITY_WINDOW_MS)
        });
        let entry = recent
            .entry(package_name.to_string())
            .or_insert(UsageWindow {
                count: 0,
                start_elapsed: now_elapsed_ms,
            });
        let active = now_elapsed_ms
            .checked_sub(entry.start_elapsed)
            .is_some_and(|e| e < UNUSUAL_ACTIVITY_WINDOW_MS);
        if active {
            entry.count = entry.count.saturating_add(1);
        } else {
            entry.count = 1;
            entry.start_elapsed = now_elapsed_ms;
        }
        let count = entry.count;
        if recent.len() > MAX_TRACKED_PACKAGES {
            if let Some(oldest) = recent
                .iter()
                .filter(|(k, _)| k.as_str() != package_name)
                .min_by_key(|(_, w)| w.start_elapsed)
                .map(|(k, _)| k.clone())
            {
                recent.remove(&oldest);
            }
        }
        count
    }

    /// Load and validate both cooling-off deadlines in a single pass, so a
    /// cooling-off decision touches each storage key only once instead of
    /// re-loading (and re-decrypting) them for separate predicates.
    fn cooled_off_state(
        &self,
        package_name: &str,
        now_elapsed_ms: u64,
        now_wall_ms: u64,
    ) -> Option<CooledOffState> {
        // An unreadable penalty must not read as "not penalised": that is how a
        // cooling-off period would be skipped by a store that cannot be read.
        let wall_until = self
            .load_u64(&key(COOLED_OFF_KEY_PREFIX, package_name))
            .ok()?
            .filter(|&u| u > 0 && now_wall_ms < u);
        let elapsed_until = self
            .load_u64(&key(COOLED_OFF_ELAPSED_KEY_PREFIX, package_name))
            .ok()?
            .filter(|&u| {
                u > 0 && now_elapsed_ms < u && u - now_elapsed_ms <= COOLING_OFF_PERIOD_MS
            });
        Some(CooledOffState {
            wall_until,
            elapsed_until,
        })
    }

    fn set_cooled_off(&self, package_name: &str, now_elapsed_ms: u64, now_wall_ms: u64) {
        self.storage.save(
            key(COOLED_OFF_KEY_PREFIX, package_name),
            (now_wall_ms + COOLING_OFF_PERIOD_MS).to_string(),
        );
        self.storage.save(
            key(COOLED_OFF_ELAPSED_KEY_PREFIX, package_name),
            (now_elapsed_ms + COOLING_OFF_PERIOD_MS).to_string(),
        );
    }

    /// `Ok(None)` is a genuinely unset key; `Err(())` is a read that failed or a
    /// value that would not decode, which callers must treat as unknown rather
    /// than as "no penalty recorded".
    #[allow(clippy::result_unit_err)]
    fn load_u64(&self, key: &str) -> Result<Option<u64>, ()> {
        match self.storage.load(key.to_string()) {
            StorageRead::Found { value } => value.parse::<u64>().map(Some).map_err(|_| ()),
            StorageRead::Absent => Ok(None),
            StorageRead::Unavailable => Err(()),
        }
    }
}

/// The validated cooling-off deadlines for a package: the wall and the
/// reconstructed-monotonic deadlines, each present only when still in the future
/// (belt-and-suspenders across a reboot or a wall-clock change).
struct CooledOffState {
    wall_until: Option<u64>,
    elapsed_until: Option<u64>,
}

impl CooledOffState {
    /// True while either deadline is still in the future.
    fn active(&self) -> bool {
        self.wall_until.is_some() || self.elapsed_until.is_some()
    }

    /// The cooling-off deadline as a wall-clock timestamp (the soonest valid of
    /// the wall and reconstructed-monotonic deadlines), or 0 if not cooled off.
    fn until_wall_ms(&self, now_elapsed_ms: u64, now_wall_ms: u64) -> u64 {
        if !self.active() {
            return 0;
        }
        let wall_expiry = self.wall_until.unwrap_or(u64::MAX);
        let elapsed_expiry = self
            .elapsed_until
            .map(|u| now_wall_ms + (u - now_elapsed_ms))
            .unwrap_or(u64::MAX);
        wall_expiry.min(elapsed_expiry)
    }
}

/// Parse a persisted `count:start_elapsed:persist_wall` window. When the stored
/// monotonic start is in the future relative to `now_elapsed_ms` (a reboot reset
/// the monotonic clock), reconstruct the start from the wall-clock anchor.
/// Mirrors keep-android `AutoSigningSafeguards.loadPersistedUsage`.
fn parse_window(raw: &str, now_elapsed_ms: u64, now_wall_ms: u64) -> Option<UsageWindow> {
    let mut parts = raw.split(':');
    let count = parts.next()?.parse::<u32>().ok()?.min(DAILY_LIMIT + 1);
    let start_elapsed = parts.next()?.parse::<u64>().ok()?;
    if start_elapsed <= now_elapsed_ms {
        return Some(UsageWindow {
            count,
            start_elapsed,
        });
    }
    let persist_wall = parts.next()?.parse::<u64>().ok()?;
    // When the wall delta is unusable (the wall clock moved backward, or jumped
    // forward past the device's uptime) or reconstructs to 0, do NOT drop the
    // window -- that would let an app reset its velocity by restarting keep.
    // Clamp it to still-active (just-started) while preserving the count.
    let start_elapsed = now_wall_ms
        .checked_sub(persist_wall)
        .and_then(|elapsed_since| now_elapsed_ms.checked_sub(elapsed_since))
        .filter(|&reconstructed| reconstructed > 0)
        .unwrap_or(now_elapsed_ms);
    Some(UsageWindow {
        count,
        start_elapsed,
    })
}

fn serialize_window(window: &UsageWindow, now_wall_ms: u64) -> String {
    format!("{}:{}:{}", window.count, window.start_elapsed, now_wall_ms)
}

/// Shared auto-approval gate for the non-Manual policies. Auto-approves only a
/// `SignEvent` of a non-sensitive kind, when opted in, the rate limiter allows
/// it, and the assessed risk stays below `max_auto_score`; everything else falls
/// to the UI. The only knob between the tiers is `max_auto_score`, so a stricter
/// tier is a strict subset of a looser one.
///
/// `current_hour` is the caller's LOCAL hour (0-23), the same value fed to
/// [`assess_signing_risk`] for display, so the score that gates this decision is
/// the score the user is shown.
fn evaluate_auto(
    ctx: SigningRequestContext,
    is_opted_in: bool,
    rate_check: AutoSignDecision,
    max_auto_score: u32,
    current_hour: u32,
) -> SignPolicyEvaluation {
    if ctx.operation != Nip55RequestType::SignEvent {
        return SignPolicyEvaluation::FallToUi;
    }

    if ctx.event_kind.is_some_and(is_sensitive_kind) {
        return SignPolicyEvaluation::FallToUi;
    }

    let recent_count = match &rate_check {
        AutoSignDecision::Allowed { recent_count, .. } => *recent_count,
        _ => 0,
    };

    let risk = assess_signing_risk(ctx, recent_count, current_hour);

    if !is_opted_in || risk.score >= max_auto_score {
        return SignPolicyEvaluation::FallToUi;
    }

    match rate_check {
        AutoSignDecision::Allowed { .. } => SignPolicyEvaluation::AutoApprove,
        _ => SignPolicyEvaluation::FallToUi,
    }
}

/// Evaluate a request against the legacy 2-value [`PolicyMode`].
///
/// `current_hour` is the caller's LOCAL hour (0-23), NOT a UTC hour, and it must
/// be the same hour the caller passes to [`assess_signing_risk`] for the prompt.
/// The `UnusualTime` risk factor is time-of-day sensitive, so a divergent hour
/// would gate the decision on a different score than the one shown to the user.
#[uniffi::export]
pub fn evaluate_sign_policy(
    policy_mode: PolicyMode,
    ctx: SigningRequestContext,
    is_opted_in: bool,
    rate_check: AutoSignDecision,
    current_hour: u32,
) -> SignPolicyEvaluation {
    match policy_mode {
        PolicyMode::Manual => SignPolicyEvaluation::FallToUi,
        PolicyMode::Auto => evaluate_auto(
            ctx,
            is_opted_in,
            rate_check,
            RISK_ESCALATION_THRESHOLD,
            current_hour,
        ),
    }
}

/// Evaluate a request against the user's 3-value [`SignPolicySelection`], giving
/// `Basic` and `Auto` distinct runtime behavior (#716) instead of collapsing both
/// onto [`PolicyMode::Auto`]:
///
/// * `Manual` always falls to the UI.
/// * `Auto` matches [`evaluate_sign_policy`] with [`PolicyMode::Auto`]: it
///   auto-approves a non-sensitive `SignEvent` up to [`RISK_ESCALATION_THRESHOLD`].
/// * `Basic` is a strict subset of `Auto` -- it auto-approves only when the
///   assessed risk stays below [`BASIC_RISK_THRESHOLD`] (the `SigningAuthLevel::None`
///   ceiling), so any request the risk model rates as needing even a PIN falls to
///   the UI. This realizes the documented "Basic implies some prompting" without
///   ever adding a blind-approve mode: neither tier auto-approves a sensitive
///   kind, an encryption op, a rate-limited burst, or a high-risk request.
///
/// `current_hour` is the caller's LOCAL hour (0-23), NOT a UTC hour, and it must
/// be the same hour the caller passes to [`assess_signing_risk`] for the prompt.
/// The `UnusualTime` risk factor is time-of-day sensitive, so a divergent hour
/// would gate the decision on a different score than the one shown to the user.
#[uniffi::export]
pub fn evaluate_sign_policy_selection(
    selection: SignPolicySelection,
    ctx: SigningRequestContext,
    is_opted_in: bool,
    rate_check: AutoSignDecision,
    current_hour: u32,
) -> SignPolicyEvaluation {
    let max_auto_score = match selection {
        SignPolicySelection::Manual => return SignPolicyEvaluation::FallToUi,
        SignPolicySelection::Basic => BASIC_RISK_THRESHOLD,
        SignPolicySelection::Auto => RISK_ESCALATION_THRESHOLD,
    };
    evaluate_auto(ctx, is_opted_in, rate_check, max_auto_score, current_hour)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx(operation: Nip55RequestType, event_kind: Option<u32>) -> SigningRequestContext {
        SigningRequestContext {
            operation,
            package_name: "com.test".to_string(),
            event_kind,
            has_signed_kind_before: true,
            app_age_ms: Some(48 * 60 * 60 * 1000),
        }
    }

    fn allowed(hourly: u32, daily: u32) -> AutoSignDecision {
        AutoSignDecision::Allowed {
            hourly_count: hourly,
            daily_count: daily,
            recent_count: 0,
            hourly_limit: HOURLY_LIMIT,
            daily_limit: DAILY_LIMIT,
        }
    }

    #[test]
    fn test_sensitive_kinds() {
        assert!(is_sensitive_kind(0));
        assert!(is_sensitive_kind(4));
        assert!(is_sensitive_kind(1059));
        assert!(is_sensitive_kind(30000));
        assert!(is_sensitive_kind(35000));
        assert!(!is_sensitive_kind(1));
        assert!(!is_sensitive_kind(7));
        assert!(!is_sensitive_kind(29999));
        assert!(!is_sensitive_kind(40000));
    }

    #[test]
    fn test_sensitive_kind_warnings() {
        assert!(sensitive_kind_warning(0).is_some());
        assert!(sensitive_kind_warning(4).is_some());
        assert!(sensitive_kind_warning(30001).is_some());
        assert!(sensitive_kind_warning(1).is_none());
    }

    #[test]
    fn test_risk_assessment_sensitive_kind() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(4));
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(result
            .factors
            .contains(&SigningRiskFactor::SensitiveEventKind));
    }

    #[test]
    fn test_risk_assessment_high_frequency() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = assess_signing_risk(ctx, 20, 12);
        assert!(result.factors.contains(&SigningRiskFactor::HighFrequency));
    }

    #[test]
    fn test_risk_assessment_unknown_age() {
        let ctx = SigningRequestContext {
            operation: Nip55RequestType::SignEvent,
            package_name: "com.test".to_string(),
            event_kind: Some(1),
            has_signed_kind_before: true,
            app_age_ms: None,
        };
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(result.factors.contains(&SigningRiskFactor::UnknownAge));
    }

    #[test]
    fn test_risk_assessment_new_app() {
        let ctx = SigningRequestContext {
            operation: Nip55RequestType::SignEvent,
            package_name: "com.test".to_string(),
            event_kind: Some(1),
            has_signed_kind_before: true,
            app_age_ms: Some(0),
        };
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(result.factors.contains(&SigningRiskFactor::NewApp));
    }

    #[test]
    fn test_risk_assessment_first_kind() {
        let ctx = SigningRequestContext {
            operation: Nip55RequestType::SignEvent,
            package_name: "com.test".to_string(),
            event_kind: Some(1),
            has_signed_kind_before: false,
            app_age_ms: Some(48 * 60 * 60 * 1000),
        };
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(result.factors.contains(&SigningRiskFactor::FirstKind));
    }

    #[test]
    fn test_risk_assessment_sensitive_operation() {
        let ctx = test_ctx(Nip55RequestType::Nip44Decrypt, None);
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(result
            .factors
            .contains(&SigningRiskFactor::SensitiveOperation));
    }

    #[test]
    fn test_risk_assessment_get_public_key_not_sensitive() {
        let ctx = test_ctx(Nip55RequestType::GetPublicKey, None);
        let result = assess_signing_risk(ctx, 0, 12);
        assert!(!result
            .factors
            .contains(&SigningRiskFactor::SensitiveOperation));
    }

    struct MockStorage {
        map: Mutex<HashMap<String, String>>,
    }
    impl MockStorage {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                map: Mutex::new(HashMap::new()),
            })
        }
    }
    impl SigningRateLimiterStorage for MockStorage {
        fn load(&self, key: String) -> StorageRead {
            match self.map.lock().unwrap().get(&key) {
                Some(value) => StorageRead::Found {
                    value: value.clone(),
                },
                None => StorageRead::Absent,
            }
        }
        fn save(&self, key: String, value: String) -> bool {
            self.map.lock().unwrap().insert(key, value);
            true
        }
        fn remove(&self, key: String) -> bool {
            self.map.lock().unwrap().remove(&key);
            true
        }
        fn clear(&self) -> bool {
            self.map.lock().unwrap().clear();
            true
        }
    }

    /// Storage whose writes never persist while reads keep working, modelling a
    /// backing file that fails silently. Drives the path where the usage counters
    /// cannot be recorded.
    struct UnwritableStorage;
    impl SigningRateLimiterStorage for UnwritableStorage {
        fn load(&self, _key: String) -> StorageRead {
            StorageRead::Absent
        }
        fn save(&self, _key: String, _value: String) -> bool {
            false
        }
        fn remove(&self, _key: String) -> bool {
            false
        }
        fn clear(&self) -> bool {
            false
        }
    }

    /// Writes land, but reads never do. Before reads failed closed this was the
    /// wider hole: an unreadable counter looked like a fresh window, so the count
    /// restarted every request and the hourly ceiling was never approached.
    struct UnreadableStorage {
        map: Mutex<HashMap<String, String>>,
    }
    impl SigningRateLimiterStorage for UnreadableStorage {
        fn load(&self, key: String) -> StorageRead {
            // Only the usage counters are unreadable. The cooling-off keys answer
            // normally so this isolates the window path: without that, the
            // cooling-off read fails closed first and the test would pass even if
            // an unreadable window were still treated as a fresh one.
            if key.starts_with(HOURLY_KEY_PREFIX) || key.starts_with(DAILY_KEY_PREFIX) {
                StorageRead::Unavailable
            } else {
                StorageRead::Absent
            }
        }
        fn save(&self, key: String, value: String) -> bool {
            self.map.lock().unwrap().insert(key, value);
            true
        }
        fn remove(&self, key: String) -> bool {
            self.map.lock().unwrap().remove(&key);
            true
        }
        fn clear(&self) -> bool {
            self.map.lock().unwrap().clear();
            true
        }
    }

    #[test]
    fn unreadable_usage_refuses_instead_of_restarting_the_window() {
        let limiter = SigningRateLimiter::new(Arc::new(UnreadableStorage {
            map: Mutex::new(HashMap::new()),
        }));
        // Well past the hourly ceiling: if an unreadable counter were treated as
        // a fresh window, every one of these would come back Allowed.
        for i in 0..(HOURLY_LIMIT + 20) {
            let result =
                limiter.check_and_record("com.test".to_string(), 1000 + i as u64, 1000 + i as u64);
            assert_eq!(
                result,
                AutoSignDecision::StorageUnavailable,
                "unknown prior usage must not be treated as no prior usage"
            );
        }
    }

    /// Stored data that will not decode is a fault, not an empty window.
    struct CorruptStorage;
    impl SigningRateLimiterStorage for CorruptStorage {
        fn load(&self, _key: String) -> StorageRead {
            StorageRead::Found {
                value: "not-a-window".to_string(),
            }
        }
        fn save(&self, _key: String, _value: String) -> bool {
            true
        }
        fn remove(&self, _key: String) -> bool {
            true
        }
        fn clear(&self) -> bool {
            true
        }
    }

    #[test]
    fn undecodable_counter_refuses_instead_of_restarting_the_window() {
        let limiter = SigningRateLimiter::new(Arc::new(CorruptStorage));
        assert_eq!(
            limiter.check_and_record("com.test".to_string(), 1000, 1000),
            AutoSignDecision::StorageUnavailable
        );
    }

    #[test]
    fn unrecordable_usage_refuses_instead_of_allowing() {
        // The counters cannot be persisted, so this request cannot be counted
        // toward the ceilings. Allowing it would let every later request reuse
        // the same un-incremented window and never reach a limit.
        let limiter = SigningRateLimiter::new(Arc::new(UnwritableStorage));
        for i in 0..5 {
            let result = limiter.check_and_record("com.test".to_string(), 1000 + i, 1000 + i);
            assert_eq!(
                result,
                AutoSignDecision::StorageUnavailable,
                "an uncounted request must not be reported as allowed"
            );
        }
    }

    #[test]
    fn unrecordable_usage_does_not_auto_approve() {
        // The decision path must treat it as a refusal, not just the limiter.
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        assert_eq!(
            evaluate_sign_policy_selection(
                SignPolicySelection::Auto,
                ctx,
                true,
                AutoSignDecision::StorageUnavailable,
                12,
            ),
            SignPolicyEvaluation::FallToUi
        );
    }

    #[test]
    fn test_rate_limiter_allowed() {
        let limiter = SigningRateLimiter::new(MockStorage::new());
        let result = limiter.check_and_record("com.test".to_string(), 1000, 1000);
        assert!(matches!(result, AutoSignDecision::Allowed { .. }));
    }

    #[test]
    fn test_rate_limiter_allowed_includes_limits() {
        let limiter = SigningRateLimiter::new(MockStorage::new());
        match limiter.check_and_record("com.test".to_string(), 1000, 1000) {
            AutoSignDecision::Allowed {
                hourly_limit,
                daily_limit,
                ..
            } => {
                assert_eq!(hourly_limit, HOURLY_LIMIT);
                assert_eq!(daily_limit, DAILY_LIMIT);
            }
            other => panic!("Expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiter_hourly_limit() {
        let limiter = SigningRateLimiter::new(MockStorage::new());
        let base = 1_000_000u64;
        let gap = 1201u64;
        for i in 0..HOURLY_LIMIT {
            let ts = base + (i as u64) * gap;
            let result = limiter.check_and_record("com.test".to_string(), ts, ts);
            assert!(
                matches!(result, AutoSignDecision::Allowed { .. }),
                "Expected Allowed at iteration {i}, got {:?}",
                result
            );
        }
        let ts = base + (HOURLY_LIMIT as u64) * gap;
        let result = limiter.check_and_record("com.test".to_string(), ts, ts);
        assert!(matches!(result, AutoSignDecision::HourlyLimitExceeded));
    }

    #[test]
    fn test_rate_limiter_denied_does_not_increment() {
        let storage = MockStorage::new();
        let limiter = SigningRateLimiter::new(storage.clone());
        let base = 1_000_000u64;
        let gap = 1201u64;
        for i in 0..HOURLY_LIMIT {
            let ts = base + (i as u64) * gap;
            limiter.check_and_record("com.test".to_string(), ts, ts);
        }
        let ts = base + (HOURLY_LIMIT as u64) * gap;
        let result = limiter.check_and_record("com.test".to_string(), ts, ts);
        assert!(matches!(result, AutoSignDecision::HourlyLimitExceeded));
        // The denied request must not bump the persisted counter past the limit.
        assert_eq!(
            limiter
                .get_usage_stats("com.test".to_string(), ts, ts)
                .hourly_count,
            HOURLY_LIMIT
        );
    }

    #[test]
    fn test_rate_limiter_cooling_off() {
        let limiter = SigningRateLimiter::new(MockStorage::new());
        let base = 1_000_000u64;
        let gap = 1201u64;
        for i in 0..=HOURLY_LIMIT {
            let ts = base + (i as u64) * gap;
            limiter.check_and_record("com.test".to_string(), ts, ts);
        }
        let ts = base + ((HOURLY_LIMIT + 1) as u64) * gap;
        let result = limiter.check_and_record("com.test".to_string(), ts, ts);
        assert!(matches!(result, AutoSignDecision::CoolingOff { .. }));
    }

    #[test]
    fn test_rate_limiter_persists_across_instances() {
        // Counters live in storage, so a fresh limiter (a keep restart) keeps
        // them -- an app cannot reset its velocity by restarting keep.
        let storage = MockStorage::new();
        let l1 = SigningRateLimiter::new(storage.clone());
        for i in 0..50u64 {
            let ts = 1_000_000 + i * 1201;
            l1.check_and_record("com.test".to_string(), ts, ts);
        }
        let l2 = SigningRateLimiter::new(storage.clone());
        let now = 1_000_000 + 50 * 1201;
        assert_eq!(
            l2.get_usage_stats("com.test".to_string(), now, now)
                .hourly_count,
            50
        );
    }

    #[test]
    fn test_rate_limiter_reboot_reconstructs_window() {
        // After a reboot the monotonic clock resets; the wall anchor keeps the
        // window alive (when the device has been up at least as long as the wall
        // gap), so the counter is not silently reset.
        let storage = MockStorage::new();
        let l1 = SigningRateLimiter::new(storage.clone());
        l1.check_and_record("com.test".to_string(), 1_000_000, 1_700_000_000_000);
        // Reboot: elapsed reset to 200_000 (200s uptime), wall advanced 60s.
        let l2 = SigningRateLimiter::new(storage.clone());
        assert_eq!(
            l2.get_usage_stats("com.test".to_string(), 200_000, 1_700_000_060_000)
                .hourly_count,
            1,
            "window survived reboot via wall anchor"
        );
    }

    #[test]
    fn test_evaluate_sign_policy_manual() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, None);
        let result = evaluate_sign_policy(PolicyMode::Manual, ctx, false, allowed(0, 0), 12);
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_sensitive() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(4));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1), 12);
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_approved() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1), 12);
        assert_eq!(result, SignPolicyEvaluation::AutoApprove);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_not_opted_in() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, false, allowed(0, 0), 12);
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_rate_limit_falls_to_ui() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy(
            PolicyMode::Auto,
            ctx,
            true,
            AutoSignDecision::HourlyLimitExceeded,
            12,
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_encrypt_falls_to_ui() {
        let ctx = test_ctx(Nip55RequestType::Nip44Encrypt, None);
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1), 12);
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    fn allowed_recent(recent: u32) -> AutoSignDecision {
        AutoSignDecision::Allowed {
            hourly_count: 1,
            daily_count: 1,
            recent_count: recent,
            hourly_limit: HOURLY_LIMIT,
            daily_limit: DAILY_LIMIT,
        }
    }

    #[test]
    fn selection_manual_always_falls_to_ui() {
        // Even a zero-risk request prompts under Manual.
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy_selection(
            SignPolicySelection::Manual,
            ctx,
            true,
            allowed(1, 1),
            12,
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn selection_basic_and_auto_auto_approve_low_risk() {
        // A non-sensitive SignEvent from a known app with no risk factors scores
        // below the None ceiling, so both tiers auto-approve it.
        for selection in [SignPolicySelection::Basic, SignPolicySelection::Auto] {
            let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
            let result = evaluate_sign_policy_selection(selection, ctx, true, allowed(1, 1), 12);
            assert_eq!(
                result,
                SignPolicyEvaluation::AutoApprove,
                "{selection:?} should auto-approve a zero-risk request"
            );
        }
    }

    #[test]
    fn selection_basic_prompts_where_auto_approves_moderate_risk() {
        // A high-frequency burst scores in the [20, 40) band: needs a PIN by the
        // risk model, so Basic (ceiling 20) prompts while Auto (ceiling 40) still
        // auto-approves. This is the distinguishing case between the two tiers.
        let auto = evaluate_sign_policy_selection(
            SignPolicySelection::Auto,
            test_ctx(Nip55RequestType::SignEvent, Some(1)),
            true,
            allowed_recent(HIGH_FREQUENCY_THRESHOLD + 1),
            12,
        );
        assert_eq!(
            auto,
            SignPolicyEvaluation::AutoApprove,
            "Auto approves moderate risk"
        );

        let basic = evaluate_sign_policy_selection(
            SignPolicySelection::Basic,
            test_ctx(Nip55RequestType::SignEvent, Some(1)),
            true,
            allowed_recent(HIGH_FREQUENCY_THRESHOLD + 1),
            12,
        );
        assert_eq!(
            basic,
            SignPolicyEvaluation::FallToUi,
            "Basic prompts on moderate risk"
        );
    }

    #[test]
    fn selection_both_tiers_prompt_on_sensitive_kind() {
        // Neither tier auto-approves a sensitive kind (no blind-approve mode).
        for selection in [SignPolicySelection::Basic, SignPolicySelection::Auto] {
            let ctx = test_ctx(Nip55RequestType::SignEvent, Some(4));
            let result = evaluate_sign_policy_selection(selection, ctx, true, allowed(1, 1), 12);
            assert_eq!(
                result,
                SignPolicyEvaluation::FallToUi,
                "{selection:?} must prompt on a sensitive kind"
            );
        }
    }

    #[test]
    fn selection_uses_the_callers_local_hour_not_a_utc_clock() {
        // A newly installed app (+15) is under the Basic ceiling (20) at a normal
        // local hour, but the UnusualTime factor (+10) pushes it to 25 at 03:00
        // local, crossing the ceiling. The evaluator must see the caller's local
        // hour, otherwise a user in a non-UTC zone gets a silent auto-approval at
        // a time the risk model rates as unusual.
        let new_app = || SigningRequestContext {
            operation: Nip55RequestType::SignEvent,
            package_name: "com.test".to_string(),
            event_kind: Some(1),
            has_signed_kind_before: true,
            app_age_ms: Some(0),
        };

        assert_eq!(
            assess_signing_risk(new_app(), 0, 12).score,
            15,
            "normal-hour score must sit under the Basic ceiling"
        );
        assert_eq!(
            assess_signing_risk(new_app(), 0, 3).score,
            25,
            "unusual-hour score must cross the Basic ceiling"
        );

        assert_eq!(
            evaluate_sign_policy_selection(
                SignPolicySelection::Basic,
                new_app(),
                true,
                allowed(1, 1),
                12,
            ),
            SignPolicyEvaluation::AutoApprove,
            "auto-approves at a normal local hour"
        );
        assert_eq!(
            evaluate_sign_policy_selection(
                SignPolicySelection::Basic,
                new_app(),
                true,
                allowed(1, 1),
                3,
            ),
            SignPolicyEvaluation::FallToUi,
            "falls to the UI at an unusual local hour"
        );
    }

    #[test]
    fn selection_both_tiers_prompt_when_not_opted_in() {
        for selection in [SignPolicySelection::Basic, SignPolicySelection::Auto] {
            let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
            let result = evaluate_sign_policy_selection(selection, ctx, false, allowed(1, 1), 12);
            assert_eq!(result, SignPolicyEvaluation::FallToUi);
        }
    }

    struct MockPolicyStorage {
        map: Mutex<HashMap<String, String>>,
    }
    impl MockPolicyStorage {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                map: Mutex::new(HashMap::new()),
            })
        }
    }
    impl SignPolicySelectionStorage for MockPolicyStorage {
        fn load(&self, key: String) -> Option<String> {
            self.map.lock().unwrap().get(&key).cloned()
        }
        fn save(&self, key: String, value: String) -> bool {
            self.map.lock().unwrap().insert(key, value);
            true
        }
        fn remove(&self, key: String) -> bool {
            self.map.lock().unwrap().remove(&key);
            true
        }
    }

    /// A store whose writes never persist, modelling a backing file that fails
    /// while an in-memory cache still answers reads. Proves the setters report
    /// the failure instead of it being invisible.
    struct FailingPolicyStorage;
    impl SignPolicySelectionStorage for FailingPolicyStorage {
        fn load(&self, _key: String) -> Option<String> {
            None
        }
        fn save(&self, _key: String, _value: String) -> bool {
            false
        }
        fn remove(&self, _key: String) -> bool {
            false
        }
    }

    #[test]
    fn setters_report_whether_the_write_persisted() {
        let ok = SignPolicyStore::new(MockPolicyStorage::new());
        assert!(ok.set_global_policy(SignPolicySelection::Basic));
        assert!(ok.set_app_override("com.example".into(), Some(SignPolicySelection::Manual)));
        assert!(ok.set_app_override("com.example".into(), None));

        // A store that cannot persist must say so, for both the set and the
        // clear: a caller that assumed success would drop the only record that
        // the old, possibly looser, selection is still in force.
        let bad = SignPolicyStore::new(Arc::new(FailingPolicyStorage));
        assert!(!bad.set_global_policy(SignPolicySelection::Auto));
        assert!(!bad.set_app_override("com.example".into(), Some(SignPolicySelection::Auto)));
        assert!(!bad.set_app_override("com.example".into(), None));
    }

    #[test]
    fn sign_policy_selection_maps_to_policy_mode() {
        assert_eq!(
            SignPolicySelection::Manual.policy_mode(),
            PolicyMode::Manual
        );
        // Basic and Auto both map to Auto today (behavior-neutral hoist).
        assert_eq!(SignPolicySelection::Basic.policy_mode(), PolicyMode::Auto);
        assert_eq!(SignPolicySelection::Auto.policy_mode(), PolicyMode::Auto);
    }

    #[test]
    fn sign_policy_selection_ordinal_round_trip_and_defaults() {
        for p in [
            SignPolicySelection::Manual,
            SignPolicySelection::Basic,
            SignPolicySelection::Auto,
        ] {
            assert_eq!(SignPolicySelection::from_ordinal(p.to_ordinal()), p);
        }
        // Unknown ordinals fail safe to Manual.
        assert_eq!(
            SignPolicySelection::from_ordinal(9),
            SignPolicySelection::Manual
        );
    }

    #[test]
    fn sign_policy_store_global_defaults_to_manual_then_persists() {
        let store = SignPolicyStore::new(MockPolicyStorage::new());
        assert_eq!(store.global_policy(), SignPolicySelection::Manual);
        store.set_global_policy(SignPolicySelection::Auto);
        assert_eq!(store.global_policy(), SignPolicySelection::Auto);
    }

    #[test]
    fn sign_policy_store_persists_across_new_instances() {
        let storage = MockPolicyStorage::new();
        SignPolicyStore::new(storage.clone()).set_global_policy(SignPolicySelection::Basic);
        // A fresh store over the same backend (a restart) reads it back.
        assert_eq!(
            SignPolicyStore::new(storage).global_policy(),
            SignPolicySelection::Basic
        );
    }

    #[test]
    fn sign_policy_store_override_precedence_and_clear() {
        let store = SignPolicyStore::new(MockPolicyStorage::new());
        store.set_global_policy(SignPolicySelection::Manual);
        // No override -> follows global.
        assert!(store.app_override("com.app".into()).is_none());
        assert_eq!(
            store.effective_policy_mode("com.app".into()),
            PolicyMode::Manual
        );
        // Override wins over global.
        store.set_app_override("com.app".into(), Some(SignPolicySelection::Auto));
        assert_eq!(
            store.app_override("com.app".into()),
            Some(SignPolicySelection::Auto)
        );
        assert_eq!(
            store.effective_policy_mode("com.app".into()),
            PolicyMode::Auto
        );
        // A different app still follows global.
        assert_eq!(
            store.effective_policy("com.other".into()),
            SignPolicySelection::Manual
        );
        // Clearing the override reverts to global.
        store.set_app_override("com.app".into(), None);
        assert!(store.app_override("com.app".into()).is_none());
        assert_eq!(
            store.effective_policy("com.app".into()),
            SignPolicySelection::Manual
        );
    }
}
