// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Rust-side integrity MAC primitives over the foreign `SecureStorage` KV
//! entries (#785).
//!
//! keep-mobile persists everything (FROST shares, the active-share pointer,
//! descriptors, config, ...) as plaintext bytes through the foreign
//! [`SecureStorage`](crate::storage::SecureStorage) trait, relying on the
//! Android Keystore / iOS Keychain layer for encryption at rest. That layer is
//! also the one an attacker with root / a malicious storage impl controls, so
//! keep-mobile currently has no independent way to detect a dropped, swapped,
//! or tampered entry.
//!
//! These functions provide the keyed-HMAC primitives to close that gap, mirroring
//! the shipped audit chain in [`crate::nip55_audit`]: the platform layer owns
//! the storage and a hardware-Keystore-held `mac_key`, and calls
//! [`storage_entry_mac`] to MAC each entry on store and [`storage_verify_entry_mac`]
//! on load, plus [`storage_tip_mac`] over the whole set (persisted in the
//! Keystore-backed slot the KV store cannot reach) so a dropped or added entry
//! is caught. Tamper-evidence rests entirely on `mac_key`: a Keystore secret an
//! attacker with only write access to the at-rest bytes cannot read. All
//! functions fail closed on an empty key.
//!
//! The scheme and detection logic are complete and tested here; wiring them into
//! the `SecureStorage` load/store paths and provisioning the Keystore key + tip
//! slot on the platform layer is the tracked follow-up.

use keep_core::crypto::hmac_sha256;

const ENTRY_MAC_DOMAIN: &[u8] = b"keep-storage-entry-mac-v1";
const TIP_MAC_DOMAIN: &[u8] = b"keep-storage-tip-mac-v1";

/// Constant-time byte compare (length check then XOR-accumulate), matching the
/// `ct_eq` used in [`crate::nip55_audit`].
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A `(entry_key, per-entry MAC)` pair, the unit the tip MAC commits to.
#[derive(uniffi::Record, Clone)]
pub struct StorageEntryMac {
    /// The storage key this MAC covers.
    pub entry_key: String,
    /// The 32-byte per-entry MAC from [`storage_entry_mac`].
    pub mac: Vec<u8>,
}

/// Per-entry MAC binding `(entry_key, value)` under `mac_key`. Length-prefix
/// framing means arbitrary `value` bytes can never be reframed as a different
/// key/value split, and including `entry_key` in the pre-image binds the MAC to
/// its slot so a ciphertext moved to another key fails verification.
///
/// Panics on an empty `mac_key` (fail closed), matching the audit-chain
/// primitives.
#[uniffi::export]
pub fn storage_entry_mac(mac_key: Vec<u8>, entry_key: String, value: Vec<u8>) -> Vec<u8> {
    assert!(
        !mac_key.is_empty(),
        "storage MAC key not initialized - cannot compute entry MAC"
    );
    let mac_key = zeroize::Zeroizing::new(mac_key);
    // `pre` holds a copy of `value` (which may be a plaintext share); wipe it.
    let mut pre = zeroize::Zeroizing::new(Vec::with_capacity(
        ENTRY_MAC_DOMAIN.len() + 16 + entry_key.len() + value.len(),
    ));
    pre.extend_from_slice(ENTRY_MAC_DOMAIN);
    pre.extend_from_slice(&(entry_key.len() as u64).to_be_bytes());
    pre.extend_from_slice(entry_key.as_bytes());
    pre.extend_from_slice(&(value.len() as u64).to_be_bytes());
    pre.extend_from_slice(&value);
    hmac_sha256(mac_key.as_slice(), pre.as_slice()).to_vec()
}

/// Verify a per-entry MAC in constant time.
#[uniffi::export]
pub fn storage_verify_entry_mac(
    mac_key: Vec<u8>,
    entry_key: String,
    value: Vec<u8>,
    expected_mac: Vec<u8>,
) -> bool {
    let computed = storage_entry_mac(mac_key, entry_key, value);
    ct_eq(&computed, &expected_mac)
}

/// Tip MAC over the whole entry set: binds the entry count and every
/// `(entry_key, per-entry MAC)` pair, sorted by key for determinism. Because the
/// tip lives in the Keystore-backed slot the KV store cannot reach, dropping,
/// adding, or tampering with any entry changes the recomputed tip and fails
/// [`storage_verify_tip_mac`], and a storage that strips per-entry MACs cannot
/// silently downgrade to "no integrity" -- the tip still demands the full set.
///
/// The tip binds each entry's key and per-entry MAC, NOT its value directly, so
/// the wired verifier MUST also verify every per-entry MAC against its value
/// (via [`storage_verify_entry_mac`]); checking only the tip would miss a value
/// swap that leaves the stored per-entry MAC in place. An absent tip (e.g. a
/// wiped Keystore slot) must be treated as a failure once integrity has been
/// initialized -- the empty-store state is `storage_tip_mac(key, [])` over
/// `count = 0`, an authenticated value, not a "skip the check" sentinel.
///
/// Panics on an empty `mac_key` (fail closed).
#[uniffi::export]
pub fn storage_tip_mac(mac_key: Vec<u8>, entries: Vec<StorageEntryMac>) -> Vec<u8> {
    assert!(
        !mac_key.is_empty(),
        "storage MAC key not initialized - cannot compute tip MAC"
    );
    let mac_key = zeroize::Zeroizing::new(mac_key);
    let mut entries = entries;
    entries.sort_by(|a, b| a.entry_key.cmp(&b.entry_key));
    let mut pre = Vec::new();
    pre.extend_from_slice(TIP_MAC_DOMAIN);
    pre.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for e in &entries {
        pre.extend_from_slice(&(e.entry_key.len() as u64).to_be_bytes());
        pre.extend_from_slice(e.entry_key.as_bytes());
        pre.extend_from_slice(&(e.mac.len() as u64).to_be_bytes());
        pre.extend_from_slice(&e.mac);
    }
    hmac_sha256(mac_key.as_slice(), &pre).to_vec()
}

/// Verify a tip MAC over the current entry set in constant time.
#[uniffi::export]
pub fn storage_verify_tip_mac(
    mac_key: Vec<u8>,
    entries: Vec<StorageEntryMac>,
    expected_tip: Vec<u8>,
) -> bool {
    let computed = storage_tip_mac(mac_key, entries);
    ct_eq(&computed, &expected_tip)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-storage-mac-key-0123456789ab";
    const KEY2: &[u8] = b"another-storage-mac-key-9876543210";

    fn em(key: &str, mac: Vec<u8>) -> StorageEntryMac {
        StorageEntryMac {
            entry_key: key.to_string(),
            mac,
        }
    }

    #[test]
    fn entry_mac_is_deterministic() {
        let a = storage_entry_mac(KEY.to_vec(), "share:aa".into(), vec![1, 2, 3]);
        let b = storage_entry_mac(KEY.to_vec(), "share:aa".into(), vec![1, 2, 3]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn entry_mac_detects_value_tamper() {
        let good = storage_entry_mac(KEY.to_vec(), "share:aa".into(), vec![1, 2, 3]);
        assert!(storage_verify_entry_mac(
            KEY.to_vec(),
            "share:aa".into(),
            vec![1, 2, 3],
            good.clone()
        ));
        // A single flipped byte in the value must fail verification.
        assert!(!storage_verify_entry_mac(
            KEY.to_vec(),
            "share:aa".into(),
            vec![1, 2, 4],
            good
        ));
    }

    #[test]
    fn entry_mac_is_bound_to_its_key() {
        // Same value under two different storage keys must produce different MACs,
        // so a ciphertext moved to another slot fails verification.
        let a = storage_entry_mac(KEY.to_vec(), "share:aa".into(), vec![9, 9]);
        let b = storage_entry_mac(KEY.to_vec(), "share:bb".into(), vec![9, 9]);
        assert_ne!(a, b);
        assert!(!storage_verify_entry_mac(
            KEY.to_vec(),
            "share:bb".into(),
            vec![9, 9],
            a
        ));
    }

    #[test]
    fn entry_mac_key_binding_and_length_framing() {
        // A different key yields a different MAC.
        let a = storage_entry_mac(KEY.to_vec(), "k".into(), vec![1]);
        let b = storage_entry_mac(KEY2.to_vec(), "k".into(), vec![1]);
        assert_ne!(a, b);
        // Length framing: ("ab", "") must not collide with ("a", "b").
        let x = storage_entry_mac(KEY.to_vec(), "ab".into(), vec![]);
        let y = storage_entry_mac(KEY.to_vec(), "a".into(), b"b".to_vec());
        assert_ne!(x, y);
    }

    #[test]
    #[should_panic(expected = "storage MAC key not initialized")]
    fn entry_mac_fails_closed_on_empty_key() {
        let _ = storage_entry_mac(vec![], "k".into(), vec![1]);
    }

    #[test]
    fn tip_detects_drop_add_and_tamper() {
        let e1 = em("a", storage_entry_mac(KEY.to_vec(), "a".into(), vec![1]));
        let e2 = em("b", storage_entry_mac(KEY.to_vec(), "b".into(), vec![2]));
        let e3 = em("c", storage_entry_mac(KEY.to_vec(), "c".into(), vec![3]));

        let tip = storage_tip_mac(KEY.to_vec(), vec![e1.clone(), e2.clone(), e3.clone()]);
        assert!(storage_verify_tip_mac(
            KEY.to_vec(),
            vec![e1.clone(), e2.clone(), e3.clone()],
            tip.clone()
        ));

        // Dropping an entry (count changes) fails.
        assert!(!storage_verify_tip_mac(
            KEY.to_vec(),
            vec![e1.clone(), e2.clone()],
            tip.clone()
        ));
        // Adding an entry fails.
        let e4 = em("d", storage_entry_mac(KEY.to_vec(), "d".into(), vec![4]));
        assert!(!storage_verify_tip_mac(
            KEY.to_vec(),
            vec![e1.clone(), e2.clone(), e3.clone(), e4],
            tip.clone()
        ));
        // Tampering one entry's MAC fails.
        let e2_bad = em("b", storage_entry_mac(KEY.to_vec(), "b".into(), vec![0xFF]));
        assert!(!storage_verify_tip_mac(
            KEY.to_vec(),
            vec![e1.clone(), e2_bad, e3.clone()],
            tip.clone()
        ));
    }

    #[test]
    fn tip_is_order_independent_for_the_same_set() {
        // A KV store has no inherent order; reordering the same set must NOT
        // change the tip (only membership/content matters).
        let e1 = em("a", storage_entry_mac(KEY.to_vec(), "a".into(), vec![1]));
        let e2 = em("b", storage_entry_mac(KEY.to_vec(), "b".into(), vec![2]));
        let t1 = storage_tip_mac(KEY.to_vec(), vec![e1.clone(), e2.clone()]);
        let t2 = storage_tip_mac(KEY.to_vec(), vec![e2, e1]);
        assert_eq!(t1, t2);
    }

    #[test]
    #[should_panic(expected = "storage MAC key not initialized")]
    fn tip_fails_closed_on_empty_key() {
        let _ = storage_tip_mac(vec![], vec![]);
    }
}
