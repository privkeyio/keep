// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-55 caller verification: the trust-on-first-use (TOFU) decision for a
//! calling app's signing certificate, and the challenge-nonce protocol. The
//! security decisions and the nonce lifecycle live here in Rust; the Android
//! layer only performs the platform capability (reading the package signing
//! certificate via `PackageManager`) and persists the trusted signature.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const NONCE_EXPIRY: Duration = Duration::from_secs(5 * 60);
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
    expires_at: Instant,
}

/// One-time challenge-nonce store for the NIP-55 notification-approval flow: a
/// nonce is issued when a request notification is shown and consumed when the
/// approval activity handles it. Monotonic `Instant` expiry (cannot be moved by
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

    /// Issue a fresh 256-bit hex nonce bound to `package_name`, expiring in five
    /// minutes. Evicts expired (then oldest) entries when the active set is full.
    pub fn generate(&self, package_name: String) -> String {
        self.generate_at(package_name, Instant::now())
    }

    /// Consume a nonce, returning the bound package when valid and unexpired. A
    /// nonce is single-use: it is removed whether or not it was still valid.
    pub fn consume(&self, nonce: String) -> Nip55NonceResult {
        self.consume_at(&nonce, Instant::now())
    }

    /// Drop expired nonces. Called opportunistically (e.g. on foreground).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        nonces.retain(|_, d| now < d.expires_at);
    }

    pub fn clear(&self) {
        self.nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Nip55NonceStore {
    fn generate_at(&self, package_name: String, now: Instant) -> String {
        let nonce = hex::encode(keep_core::crypto::random_bytes::<32>());
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        nonces.insert(
            nonce.clone(),
            NonceData {
                package_name,
                expires_at: now + NONCE_EXPIRY,
            },
        );
        if nonces.len() > MAX_ACTIVE_NONCES {
            nonces.retain(|_, d| now < d.expires_at);
            if nonces.len() > MAX_ACTIVE_NONCES {
                evict_oldest(&mut nonces);
            }
        }
        nonce
    }

    fn consume_at(&self, nonce: &str, now: Instant) -> Nip55NonceResult {
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        match nonces.remove(nonce) {
            None => Nip55NonceResult::Invalid,
            Some(d) if now >= d.expires_at => Nip55NonceResult::Expired,
            Some(d) => Nip55NonceResult::Valid {
                package_name: d.package_name,
            },
        }
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
    let mut by_expiry: Vec<(String, Instant)> = nonces
        .iter()
        .map(|(k, d)| (k.clone(), d.expires_at))
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
        let t0 = Instant::now();
        let nonce = store.generate_at("com.app".into(), t0);
        assert_eq!(
            store.consume_at(&nonce, t0 + Duration::from_secs(1)),
            Nip55NonceResult::Valid {
                package_name: "com.app".into()
            }
        );
        // Single-use: a second consume is Invalid.
        assert_eq!(
            store.consume_at(&nonce, t0 + Duration::from_secs(1)),
            Nip55NonceResult::Invalid
        );
    }

    #[test]
    fn expired_nonce_is_rejected() {
        let store = Nip55NonceStore::new();
        let t0 = Instant::now();
        let nonce = store.generate_at("com.app".into(), t0);
        assert_eq!(
            store.consume_at(&nonce, t0 + Duration::from_secs(6 * 60)),
            Nip55NonceResult::Expired
        );
    }

    #[test]
    fn unknown_nonce_is_invalid() {
        let store = Nip55NonceStore::new();
        assert_eq!(store.consume("deadbeef".into()), Nip55NonceResult::Invalid);
    }
}
