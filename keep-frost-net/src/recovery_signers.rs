// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Registry mapping recovery-tier xpub fingerprints to external NIP-46 signers.
//!
//! When a recovery tier contains `KeySlot::External { fingerprint, .. }` slots,
//! the keep node holding the descriptor needs to know which physical signer
//! holds the secret for each fingerprint. This module defines a small trait
//! (`RecoverySignerRegistry`) plus a default in-memory implementation; the
//! actual NIP-46 client invocation that consumes the resolved
//! `RecoverySignerHandle` lives in the application layer (cli/desktop/mobile)
//! to keep `keep-frost-net` free of a `keep-nip46` dependency.

use std::collections::HashMap;

use parking_lot::RwLock;
use zeroize::Zeroizing;

/// A resolved external recovery signer. The bunker URI is wrapped in
/// `Zeroizing` because it may embed a single-use connect secret.
#[derive(Clone)]
pub struct RecoverySignerHandle {
    /// Friendly label set at registration time (e.g. `"coldcard-backup"`).
    pub label: String,
    /// Bunker URI (`bunker://...?relay=...&secret=...`) to connect to.
    pub bunker_uri: Zeroizing<String>,
}

impl std::fmt::Debug for RecoverySignerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverySignerHandle")
            .field("label", &self.label)
            .field("bunker_uri", &"<redacted>")
            .finish()
    }
}

/// Resolves an xpub fingerprint to a signer connection. Implementations are
/// expected to be cheap to call and safe to invoke from any thread.
pub trait RecoverySignerRegistry: Send + Sync {
    /// Returns the signer handle for `fingerprint` (case-insensitive,
    /// 8-hex-char BIP-32 master fingerprint), or `None` if the application
    /// has not registered an external signer for that key.
    fn resolve(&self, fingerprint: &str) -> Option<RecoverySignerHandle>;
}

/// In-memory `RecoverySignerRegistry` backed by a `HashMap`.
#[derive(Default)]
pub struct InMemoryRecoverySignerRegistry {
    entries: RwLock<HashMap<String, RecoverySignerHandle>>,
}

impl InMemoryRecoverySignerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the handle for `fingerprint`. Fingerprint matching
    /// is case-insensitive; the key is stored lowercase. The bunker URI is
    /// taken as `Zeroizing<String>` so callers can preserve the wrapper end-
    /// to-end and avoid a plain-`String` hop across the boundary.
    pub fn insert(&self, fingerprint: &str, label: String, bunker_uri: Zeroizing<String>) {
        self.entries.write().insert(
            fingerprint.to_ascii_lowercase(),
            RecoverySignerHandle { label, bunker_uri },
        );
    }

    pub fn remove(&self, fingerprint: &str) -> Option<RecoverySignerHandle> {
        self.entries
            .write()
            .remove(&fingerprint.to_ascii_lowercase())
    }

    pub fn fingerprints(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }
}

impl RecoverySignerRegistry for InMemoryRecoverySignerRegistry {
    fn resolve(&self, fingerprint: &str) -> Option<RecoverySignerHandle> {
        self.entries
            .read()
            .get(&fingerprint.to_ascii_lowercase())
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_is_case_insensitive() {
        let reg = InMemoryRecoverySignerRegistry::new();
        reg.insert(
            "ABCDEF01",
            "coldcard-backup".into(),
            Zeroizing::new("bunker://x".into()),
        );
        let h = reg.resolve("abcdef01").expect("resolves lowercase");
        assert_eq!(h.label, "coldcard-backup");
        assert_eq!(&*h.bunker_uri, "bunker://x");
        assert!(reg.resolve("ABCDef01").is_some());
        assert!(reg.resolve("not-registered").is_none());
    }

    #[test]
    fn remove_returns_handle_and_clears() {
        let reg = InMemoryRecoverySignerRegistry::new();
        reg.insert(
            "a1b2c3d4",
            "sig".into(),
            Zeroizing::new("bunker://y".into()),
        );
        let removed = reg.remove("A1B2C3D4").expect("removed");
        assert_eq!(removed.label, "sig");
        assert!(reg.resolve("a1b2c3d4").is_none());
    }

    #[test]
    fn handle_debug_redacts_uri() {
        let h = RecoverySignerHandle {
            label: "lbl".into(),
            bunker_uri: Zeroizing::new("bunker://secret?secret=topsecret".into()),
        };
        let s = format!("{h:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("topsecret"));
    }
}
