// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::nip55::Nip55RequestType;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// NOTE: `Basic` and `Auto` currently map to the SAME evaluation mode
/// (`PolicyMode::Auto`), reproducing keep-android's present behavior where the
/// two are indistinguishable at runtime (the only client branch collapses both
/// to `PolicyMode::Auto`). Giving `Basic` a distinct curated-allow-set semantics
/// is a separate product decision (#716) and is intentionally NOT implemented
/// here; this type only hoists the SELECTION state into the core, behavior-neutral.
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

    /// Map the selection onto the evaluation mode. `Basic` and `Auto` both map
    /// to `Auto` today (behavior-neutral hoist); see the type note.
    pub fn policy_mode(self) -> PolicyMode {
        match self {
            SignPolicySelection::Manual => PolicyMode::Manual,
            SignPolicySelection::Basic | SignPolicySelection::Auto => PolicyMode::Auto,
        }
    }
}

/// Persistence for the sign-policy selection (global + per-app override). A
/// simple string key/value store; the Android side backs it with its encrypted
/// sign-policy prefs. Mirrors [`SigningRateLimiterStorage`].
#[uniffi::export(with_foreign)]
pub trait SignPolicySelectionStorage: Send + Sync {
    fn load(&self, key: String) -> Option<String>;
    fn save(&self, key: String, value: String);
    fn remove(&self, key: String);
}

const GLOBAL_SIGN_POLICY_KEY: &str = "global_sign_policy";

fn app_override_key(package: &str) -> String {
    format!("sign_policy_override:{package}")
}

/// Core-owned store for the sign-policy selection, so the selection state and
/// its override -> global -> Manual precedence live in one place rather than
/// being reimplemented in each client (#716). Feeds the existing evaluation via
/// [`SignPolicyStore::effective_policy_mode`].
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

    /// Persist the global sign-policy selection.
    pub fn set_global_policy(&self, policy: SignPolicySelection) {
        self.storage.save(
            GLOBAL_SIGN_POLICY_KEY.to_string(),
            policy.to_ordinal().to_string(),
        );
    }

    /// The per-app override, or `None` if the app follows the global policy.
    pub fn app_override(&self, package: String) -> Option<SignPolicySelection> {
        self.storage
            .load(app_override_key(&package))
            .and_then(|s| s.parse::<u8>().ok())
            .map(SignPolicySelection::from_ordinal)
    }

    /// Set (`Some`) or clear (`None`) the per-app override.
    pub fn set_app_override(&self, package: String, policy: Option<SignPolicySelection>) {
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

    /// The evaluation [`PolicyMode`] for a package, ready to feed the existing
    /// `evaluate_sign_policy` / decision machinery.
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
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
    fn load(&self, key: String) -> Option<String>;
    fn save(&self, key: String, value: String);
    fn remove(&self, key: String);
    fn clear(&self);
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

        let cooled = self.cooled_off_state(&package_name, now_elapsed_ms, now_wall_ms);
        if cooled.active() {
            return AutoSignDecision::CoolingOff {
                until_ms: cooled.until_wall_ms(now_elapsed_ms, now_wall_ms),
            };
        }

        // Compute would-be counts first; a denied request must not increment the
        // persisted counter, so the windows are only saved once every limit
        // passes.
        let hourly = self.next_window(
            HOURLY_KEY_PREFIX,
            &package_name,
            HOUR_MS,
            now_elapsed_ms,
            now_wall_ms,
        );
        if hourly.count > HOURLY_LIMIT {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::HourlyLimitExceeded;
        }

        let daily = self.next_window(
            DAILY_KEY_PREFIX,
            &package_name,
            DAY_MS,
            now_elapsed_ms,
            now_wall_ms,
        );
        if daily.count > DAILY_LIMIT {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::DailyLimitExceeded;
        }

        let recent = self.bump_recent(&package_name, now_elapsed_ms);
        if recent > UNUSUAL_ACTIVITY_THRESHOLD {
            self.set_cooled_off(&package_name, now_elapsed_ms, now_wall_ms);
            return AutoSignDecision::UnusualActivity;
        }

        self.save_window(HOURLY_KEY_PREFIX, &package_name, &hourly, now_wall_ms);
        self.save_window(DAILY_KEY_PREFIX, &package_name, &daily, now_wall_ms);

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
            .map(|w| w.count)
            .unwrap_or(0);
        let daily_count = self
            .read_window(
                DAILY_KEY_PREFIX,
                &package_name,
                DAY_MS,
                now_elapsed_ms,
                now_wall_ms,
            )
            .map(|w| w.count)
            .unwrap_or(0);
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
    ) -> Option<UsageWindow> {
        let raw = self.storage.load(key(prefix, package_name))?;
        let window = parse_window(&raw, now_elapsed_ms, now_wall_ms)?;
        let active = now_elapsed_ms
            .checked_sub(window.start_elapsed)
            .is_some_and(|elapsed| elapsed < window_ms);
        active.then_some(window)
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
    ) -> UsageWindow {
        match self.read_window(prefix, package_name, window_ms, now_elapsed_ms, now_wall_ms) {
            Some(mut w) => {
                w.count = w.count.saturating_add(1);
                w
            }
            None => UsageWindow {
                count: 1,
                start_elapsed: now_elapsed_ms,
            },
        }
    }

    fn save_window(
        &self,
        prefix: &str,
        package_name: &str,
        window: &UsageWindow,
        now_wall_ms: u64,
    ) {
        self.storage.save(
            key(prefix, package_name),
            serialize_window(window, now_wall_ms),
        );
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
    ) -> CooledOffState {
        let wall_until = self
            .load_u64(&key(COOLED_OFF_KEY_PREFIX, package_name))
            .filter(|&u| u > 0 && now_wall_ms < u);
        let elapsed_until = self
            .load_u64(&key(COOLED_OFF_ELAPSED_KEY_PREFIX, package_name))
            .filter(|&u| {
                u > 0 && now_elapsed_ms < u && u - now_elapsed_ms <= COOLING_OFF_PERIOD_MS
            });
        CooledOffState {
            wall_until,
            elapsed_until,
        }
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

    fn load_u64(&self, key: &str) -> Option<u64> {
        self.storage.load(key.to_string())?.parse::<u64>().ok()
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

#[uniffi::export]
pub fn evaluate_sign_policy(
    policy_mode: PolicyMode,
    ctx: SigningRequestContext,
    is_opted_in: bool,
    rate_check: AutoSignDecision,
) -> SignPolicyEvaluation {
    if policy_mode == PolicyMode::Manual {
        return SignPolicyEvaluation::FallToUi;
    }

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

    let current_hour = ((now_ms() / 1000 % 86400) / 3600) as u32;
    let risk = assess_signing_risk(ctx, recent_count, current_hour);

    if !is_opted_in || risk.score >= RISK_ESCALATION_THRESHOLD {
        return SignPolicyEvaluation::FallToUi;
    }

    match rate_check {
        AutoSignDecision::Allowed { .. } => SignPolicyEvaluation::AutoApprove,
        _ => SignPolicyEvaluation::FallToUi,
    }
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
        fn load(&self, key: String) -> Option<String> {
            self.map.lock().unwrap().get(&key).cloned()
        }
        fn save(&self, key: String, value: String) {
            self.map.lock().unwrap().insert(key, value);
        }
        fn remove(&self, key: String) {
            self.map.lock().unwrap().remove(&key);
        }
        fn clear(&self) {
            self.map.lock().unwrap().clear();
        }
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
        let result = evaluate_sign_policy(PolicyMode::Manual, ctx, false, allowed(0, 0));
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_sensitive() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(4));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1));
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_approved() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1));
        assert_eq!(result, SignPolicyEvaluation::AutoApprove);
    }

    #[test]
    fn test_evaluate_sign_policy_auto_not_opted_in() {
        let ctx = test_ctx(Nip55RequestType::SignEvent, Some(1));
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, false, allowed(0, 0));
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
        );
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
    }

    #[test]
    fn test_evaluate_sign_policy_encrypt_falls_to_ui() {
        let ctx = test_ctx(Nip55RequestType::Nip44Encrypt, None);
        let result = evaluate_sign_policy(PolicyMode::Auto, ctx, true, allowed(1, 1));
        assert_eq!(result, SignPolicyEvaluation::FallToUi);
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
        fn save(&self, key: String, value: String) {
            self.map.lock().unwrap().insert(key, value);
        }
        fn remove(&self, key: String) {
            self.map.lock().unwrap().remove(&key);
        }
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
