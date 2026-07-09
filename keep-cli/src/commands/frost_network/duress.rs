// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Duress-mode keying and provisioning (coercion resistance, inc1b).
//!
//! A duress credential distinct from the vault password lets a coerced holder
//! fail closed and emit a signed duress beacon. This module derives the
//! dedicated beacon keypair from that credential and provisions it.

use keep_core::crypto::{derive_key, Argon2Params, SALT_SIZE};
use keep_core::error::{KeepError, Result};
use nostr_sdk::prelude::*;
use secrecy::ExposeSecret;

use crate::commands::get_duress_credential;
use crate::output::Output;

/// Argon2id parameters for the duress-beacon key: HIGH (512 MiB / 6 iters), NOT
/// the vault default. The beacon's only protection against a leaked (cluster-
/// shared) pinned pubkey is the KDF cost , unlike the vault password it does not
/// also sit behind an encrypted-blob threshold , and it is derived rarely (once
/// at provision, once per serve start), so the extra cost is free UX-wise and
/// materially raises the offline brute-force cost of a low-entropy credential.
/// `serve` MUST use the same params or its re-derivation will not match.
const DURESS_BEACON_ARGON2: Argon2Params = Argon2Params::HIGH;

/// Derive the duress-beacon nostr keypair from a duress credential and salt via
/// the same vetted Argon2id path the vault uses (`keep_core::crypto::derive_key`),
/// so no new key-derivation crypto is introduced. Deterministic: the same
/// `(credential, salt)` always yields the same key. That determinism is what lets
/// `serve` detect duress (re-derive from the entered password, compare the pubkey
/// to the pinned one) and what lets the cluster pin the pubkey at provisioning.
///
/// SECURITY: a duress credential is typically low-entropy (human-memorable).
/// Argon2id raises the offline brute-force cost but does not eliminate it, so the
/// derived pubkey (shared with the cluster) is sensitive: an attacker who learns
/// it can grind the credential space to recover the beacon key and forge freeze
/// alerts. Use a strong duress credential and treat the pinned pubkey as protected.
pub(crate) fn derive_beacon_key(
    credential: &str,
    salt: &[u8; SALT_SIZE],
    params: Argon2Params,
) -> Result<Keys> {
    let derived = derive_key(credential.as_bytes(), salt, params)?;
    let bytes = derived.decrypt()?;
    let secret = SecretKey::from_slice(&bytes[..])
        .map_err(|e| KeepError::invalid_input(format!("derive beacon key: {e}")))?;
    Ok(Keys::new(secret))
}

/// `keep frost network duress-provision`: interactively provision a duress
/// credential and print the beacon pubkey (to pin with the cluster) plus the salt
/// (to configure on `serve`). Purely local , it derives, prints, and forgets. The
/// credential itself is NEVER stored (serve re-derives from the entered password
/// and compares the pubkey), so a coercer inspecting config finds only a pubkey
/// and a salt, not the duress trigger.
pub fn cmd_frost_network_duress_provision(out: &Output) -> Result<()> {
    out.header("Duress Provisioning");
    out.warn(
        "Choose a DURESS credential DISTINCT from your vault password. Entering it at `serve` \
         triggers duress mode: the holder fails closed (withholds its OPRF share so the box drops \
         below threshold) and publishes a signed alert. Make it memorable and secret; it is never \
         stored.",
    );
    let credential = get_duress_credential("Enter duress credential", "Confirm duress credential")?;
    let salt: [u8; SALT_SIZE] = keep_core::entropy::try_random_bytes()?;
    let beacon = derive_beacon_key(credential.expose_secret(), &salt, DURESS_BEACON_ARGON2)?;
    let npub = beacon
        .public_key()
        .to_bech32()
        .map_err(|e| KeepError::runtime(format!("encode beacon npub: {e}")))?;

    out.newline();
    out.field("Beacon pubkey (pin with the cluster)", &npub);
    out.field(
        "Salt (configure on serve: --duress-beacon-salt)",
        &hex::encode(salt),
    );
    out.newline();
    out.info(
        "Register the beacon pubkey with the cluster (like an attestation AK pin) and set both \
         values on `serve`. Do NOT store the duress credential anywhere.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use fast params (keep_core's Argon2Params::TESTING is cfg(test)-gated
    // and not reachable here); production uses DURESS_BEACON_ARGON2 (HIGH).
    // Determinism/variance hold for any fixed params.
    const P: Argon2Params = Argon2Params {
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn derive_beacon_key_is_deterministic() {
        let salt = [7u8; SALT_SIZE];
        let a = derive_beacon_key("correct horse battery staple", &salt, P).unwrap();
        let b = derive_beacon_key("correct horse battery staple", &salt, P).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn derive_beacon_key_varies_by_credential_and_salt() {
        let salt = [7u8; SALT_SIZE];
        let base = derive_beacon_key("cred-a", &salt, P).unwrap().public_key();
        // A different credential yields a different beacon key.
        assert_ne!(
            base,
            derive_beacon_key("cred-b", &salt, P).unwrap().public_key()
        );
        // A different salt yields a different beacon key.
        assert_ne!(
            base,
            derive_beacon_key("cred-a", &[9u8; SALT_SIZE], P)
                .unwrap()
                .public_key()
        );
    }
}
