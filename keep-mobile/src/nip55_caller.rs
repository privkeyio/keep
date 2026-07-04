// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-55 caller verification: the trust-on-first-use (TOFU) decision for a
//! calling app's signing certificate, and the challenge-nonce protocol. The
//! security decisions and the nonce lifecycle live here in Rust; the Android
//! layer only performs the platform capability (reading the package signing
//! certificate via `PackageManager`) and persists the trusted signature.

use std::collections::HashMap;
use std::sync::Mutex;

const NONCE_EXPIRY_MS: u64 = 5 * 60 * 1000;
const MAX_ACTIVE_NONCES: usize = 1000;

/// Outcome of comparing a caller's current signing-certificate hash against the
/// trusted one. Mirrors keep-android's `CallerVerificationStore.VerificationResult`.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55CallerVerification {
    /// The package is not installed / has no signature.
    NotInstalled,
    /// No signature is trusted yet; first use requires explicit approval.
    FirstUseRequiresApproval { signature: String },
    /// Current signature matches the trusted one.
    Verified { signature: String },
    /// Current signature differs from the trusted one (re-signed or spoofed).
    SignatureMismatch { expected: String, actual: String },
}

/// Constant-time string compare (length check then XOR-accumulate), matching the
/// Android `MessageDigest.isEqual` used on signature hashes.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decide whether to trust a caller. `current_signature` is the live cert hash
/// from `PackageManager` (`None` when not installed); `trusted_signature` is the
/// persisted one (`None` on first use). Mirrors
/// `CallerVerificationStore.verifyOrTrust`.
#[uniffi::export]
pub fn nip55_verify_caller(
    current_signature: Option<String>,
    trusted_signature: Option<String>,
) -> Nip55CallerVerification {
    let Some(current) = current_signature else {
        return Nip55CallerVerification::NotInstalled;
    };
    // An empty hash is not a verifiable identity. Fail closed so it can never be
    // persisted as the trusted value and later collide with another empty-hash
    // caller via `ct_eq("", "")`.
    if current.is_empty() {
        return Nip55CallerVerification::NotInstalled;
    }
    let Some(trusted) = trusted_signature else {
        return Nip55CallerVerification::FirstUseRequiresApproval { signature: current };
    };
    if ct_eq(&trusted, &current) {
        Nip55CallerVerification::Verified { signature: current }
    } else {
        Nip55CallerVerification::SignatureMismatch {
            expected: trusted,
            actual: current,
        }
    }
}

/// Result of consuming a one-time challenge nonce. Mirrors
/// `CallerVerificationStore.NonceResult`.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum Nip55NonceResult {
    Valid { package_name: String },
    Invalid,
    Expired,
}

struct NonceData {
    package_name: String,
    expires_at_ms: u64,
}

/// One-time challenge-nonce store for the NIP-55 notification-approval flow: a
/// nonce is issued when a request notification is shown and consumed when the
/// approval activity handles it. Expiry is measured on an injected boot-time
/// clock (`elapsedRealtime` millis, which counts suspend and cannot be moved by
/// a wall-clock change) and a single-use guarantee (consume removes the entry).
#[derive(uniffi::Object)]
pub struct Nip55NonceStore {
    nonces: Mutex<HashMap<String, NonceData>>,
}

impl Default for Nip55NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl Nip55NonceStore {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh 256-bit hex nonce bound to `package_name`, expiring five
    /// minutes after `now_elapsed_ms` (an `elapsedRealtime` boot-time millis
    /// value). Evicts expired (then oldest) entries when the active set is full.
    pub fn generate(&self, package_name: String, now_elapsed_ms: u64) -> String {
        let nonce = hex::encode(keep_core::crypto::random_bytes::<32>());
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        nonces.insert(
            nonce.clone(),
            NonceData {
                package_name,
                expires_at_ms: now_elapsed_ms.saturating_add(NONCE_EXPIRY_MS),
            },
        );
        if nonces.len() > MAX_ACTIVE_NONCES {
            nonces.retain(|_, d| now_elapsed_ms < d.expires_at_ms);
            if nonces.len() > MAX_ACTIVE_NONCES {
                evict_oldest(&mut nonces);
            }
        }
        nonce
    }

    /// Consume a nonce, returning the bound package when valid and unexpired. A
    /// nonce is single-use: it is removed whether or not it was still valid.
    ///
    /// Expiry is measured on the injected CLOCK_BOOTTIME (`elapsedRealtime`)
    /// millis value: it counts time spent in device suspend (the #597 fix, where
    /// a monotonic `Instant` would pause and silently stretch the window) while
    /// still resisting wall-clock manipulation. Because that clock now crosses
    /// the FFI boundary, the Kotlin clock-anomaly clause (`expiresAt - now >
    /// NONCE_EXPIRY`) is live here: a backward boot-time jump can leave a
    /// future-dated entry more than the window ahead of `now`, so treat it as
    /// Expired rather than trusting the stale expiry.
    pub fn consume(&self, nonce: String, now_elapsed_ms: u64) -> Nip55NonceResult {
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        match nonces.remove(&nonce) {
            None => Nip55NonceResult::Invalid,
            Some(d) if now_elapsed_ms >= d.expires_at_ms => Nip55NonceResult::Expired,
            Some(d) if d.expires_at_ms.saturating_sub(now_elapsed_ms) > NONCE_EXPIRY_MS => {
                Nip55NonceResult::Expired
            }
            Some(d) => Nip55NonceResult::Valid {
                package_name: d.package_name,
            },
        }
    }

    /// Drop expired nonces. Called opportunistically (e.g. on foreground).
    pub fn cleanup_expired(&self, now_elapsed_ms: u64) {
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        nonces.retain(|_, d| now_elapsed_ms < d.expires_at_ms);
    }

    pub fn clear(&self) {
        self.nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Drop the oldest-expiring nonces until the set is at most half of the cap, so
/// a flood of fresh nonces cannot evict the whole table to one entry. Mirrors
/// the Android `evictOldestNonces`.
fn evict_oldest(nonces: &mut HashMap<String, NonceData>) {
    let target = MAX_ACTIVE_NONCES / 2;
    if nonces.len() <= target {
        return;
    }
    let mut by_expiry: Vec<(String, u64)> = nonces
        .iter()
        .map(|(k, d)| (k.clone(), d.expires_at_ms))
        .collect();
    by_expiry.sort_by_key(|(_, e)| *e);
    let remove_count = nonces.len() - target;
    for (key, _) in by_expiry.into_iter().take(remove_count) {
        nonces.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_installed_when_no_current_signature() {
        assert_eq!(
            nip55_verify_caller(None, Some("abc".into())),
            Nip55CallerVerification::NotInstalled
        );
    }

    #[test]
    fn first_use_when_no_trusted_signature() {
        assert_eq!(
            nip55_verify_caller(Some("abc".into()), None),
            Nip55CallerVerification::FirstUseRequiresApproval {
                signature: "abc".into()
            }
        );
    }

    #[test]
    fn verified_on_match() {
        assert_eq!(
            nip55_verify_caller(Some("abc".into()), Some("abc".into())),
            Nip55CallerVerification::Verified {
                signature: "abc".into()
            }
        );
    }

    #[test]
    fn mismatch_is_reported_with_both_hashes() {
        assert_eq!(
            nip55_verify_caller(Some("new".into()), Some("old".into())),
            Nip55CallerVerification::SignatureMismatch {
                expected: "old".into(),
                actual: "new".into()
            }
        );
    }

    #[test]
    fn nonce_round_trip_is_valid_and_single_use() {
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let nonce = store.generate("com.app".into(), t0);
        assert_eq!(
            store.consume(nonce.clone(), t0 + 1000),
            Nip55NonceResult::Valid {
                package_name: "com.app".into()
            }
        );
        // Single-use: a second consume is Invalid.
        assert_eq!(
            store.consume(nonce, t0 + 1000),
            Nip55NonceResult::Invalid
        );
    }

    #[test]
    fn expired_nonce_is_rejected() {
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let nonce = store.generate("com.app".into(), t0);
        assert_eq!(
            store.consume(nonce, t0 + 6 * 60 * 1000),
            Nip55NonceResult::Expired
        );
    }

    #[test]
    fn nonce_expiry_counts_boot_time_millis() {
        // #597: expiry is measured on injected elapsedRealtime millis, so a
        // nonce is Valid just under five minutes and Expired at exactly the
        // five-minute boundary.
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let nonce = store.generate("com.app".into(), t0);
        assert!(matches!(
            store.consume(nonce, t0 + NONCE_EXPIRY_MS - 1),
            Nip55NonceResult::Valid { .. }
        ));

        let store = Nip55NonceStore::new();
        let nonce = store.generate("com.app".into(), t0);
        assert_eq!(
            store.consume(nonce, t0 + NONCE_EXPIRY_MS),
            Nip55NonceResult::Expired
        );
    }

    #[test]
    fn nonce_anomalous_future_expiry_is_rejected() {
        // A backward boot-time jump can leave an entry more than a full window
        // ahead of `now`; the anomaly guard treats it as Expired.
        let store = Nip55NonceStore::new();
        let generated_at: u64 = 10 * NONCE_EXPIRY_MS;
        let nonce = store.generate("com.app".into(), generated_at);
        // `now` is far below the stored expiry (clock jumped backward).
        assert_eq!(
            store.consume(nonce, 0),
            Nip55NonceResult::Expired
        );
    }

    #[test]
    fn unknown_nonce_is_invalid() {
        let store = Nip55NonceStore::new();
        assert_eq!(store.consume("deadbeef".into(), 1_000), Nip55NonceResult::Invalid);
    }

    #[test]
    fn empty_current_signature_is_not_installed() {
        // An empty hash must not be treated as a verifiable identity, on either
        // first use or comparison against an empty trusted value.
        assert_eq!(
            nip55_verify_caller(Some(String::new()), None),
            Nip55CallerVerification::NotInstalled
        );
        assert_eq!(
            nip55_verify_caller(Some(String::new()), Some(String::new())),
            Nip55CallerVerification::NotInstalled
        );
    }

    #[test]
    fn eviction_trims_to_half_keeping_newest() {
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let mut nonces = Vec::new();
        // One past the cap triggers eviction down to MAX/2, keeping the
        // newest-expiring entries.
        for i in 0..=MAX_ACTIVE_NONCES {
            let now = t0 + i as u64;
            nonces.push(store.generate(format!("pkg{i}"), now));
        }
        // The oldest nonce was evicted.
        assert_eq!(
            store.consume(nonces[0].clone(), t0 + 1000),
            Nip55NonceResult::Invalid
        );
        // The newest nonce was retained.
        let newest = nonces.last().unwrap().clone();
        let newest_now = t0 + MAX_ACTIVE_NONCES as u64;
        assert!(matches!(
            store.consume(newest, newest_now + 1000),
            Nip55NonceResult::Valid { .. }
        ));
    }

    #[test]
    fn cleanup_expired_drops_only_expired() {
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let old = store.generate("old".into(), t0);
        let fresh = store.generate("fresh".into(), t0 + 4 * 60 * 1000);
        // `old` has expired, `fresh` has not.
        let now = t0 + NONCE_EXPIRY_MS + 30 * 1000;
        store.cleanup_expired(now);
        assert_eq!(store.consume(old, now), Nip55NonceResult::Invalid);
        assert!(matches!(
            store.consume(fresh, now),
            Nip55NonceResult::Valid { .. }
        ));
    }

    #[test]
    fn clear_removes_all_nonces() {
        let store = Nip55NonceStore::new();
        let t0: u64 = 1_000;
        let nonce = store.generate("com.app".into(), t0);
        store.clear();
        assert_eq!(
            store.consume(nonce, t0 + 1000),
            Nip55NonceResult::Invalid
        );
    }
}
