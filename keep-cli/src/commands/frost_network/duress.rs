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

/// Constant-time equality of two x-only pubkeys, so duress detection does not
/// leak (via timing) whether the entered password matched the pinned beacon key.
/// The dominating cost is the Argon2 re-derivation (which runs for every serve
/// regardless), so the paths are timing-indistinguishable.
fn ct_pubkey_eq(a: &PublicKey, b: &PublicKey) -> bool {
    let (a, b) = (a.to_bytes(), b.to_bytes());
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// If `password` is the duress credential, return the beacon `Keys`; otherwise
/// `None`. Re-derives the beacon key from the entered password (same HIGH params
/// as provisioning) and constant-time-compares its pubkey to the pinned
/// `beacon_pubkey`. A single Argon2 derivation, run for EVERY serve unlock, so a
/// normal password and the duress credential are indistinguishable by timing.
pub(crate) fn match_duress(
    password: &str,
    salt: &[u8; SALT_SIZE],
    beacon_pubkey: &PublicKey,
) -> Result<Option<Keys>> {
    let candidate = derive_beacon_key(password, salt, DURESS_BEACON_ARGON2)?;
    if ct_pubkey_eq(&candidate.public_key(), beacon_pubkey) {
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
}

/// Parse the serve-side duress config: the pinned beacon `npub` and the hex salt.
pub(crate) fn parse_duress_config(
    beacon_npub: &str,
    salt_hex: &str,
) -> Result<(PublicKey, [u8; SALT_SIZE])> {
    let pubkey = PublicKey::from_bech32(beacon_npub.trim())
        .map_err(|e| KeepError::invalid_input(format!("--duress-beacon-pubkey: {e}")))?;
    let raw = hex::decode(salt_hex.trim())
        .map_err(|e| KeepError::invalid_input(format!("--duress-beacon-salt not hex: {e}")))?;
    let salt: [u8; SALT_SIZE] = raw.try_into().map_err(|_| {
        KeepError::invalid_input("--duress-beacon-salt must be 32 bytes".to_string())
    })?;
    Ok((pubkey, salt))
}

/// The duress serve path: fail CLOSED (never unlock the vault or load the OPRF
/// share, so this holder answers no evaluations and the box drops below
/// threshold) and publish ONE signed duress beacon, then stay resident so the
/// holder looks online but simply never answers. Reached only when the entered
/// password derived the pinned beacon key.
///
/// The screen mirrors a normal serve start using data knowable without the vault
/// (group, relay). The `Share`/`Threshold`/`Attestation` lines a normal serve
/// derives from the unlocked share are the DOCUMENTED residual: full byte-level
/// output and on-wire indistinguishability is a follow-up (deep-research open
/// question, tracked with the inc2 wire-format release gate). The load-bearing
/// coercion property is that the box stays locked , this fail-closed path plus the
/// inc2 sticky freeze , invariant to which password was entered.
pub(crate) async fn run_duress_serve(
    out: &Output,
    beacon: &Keys,
    group_pubkey: &[u8; 32],
    relay: &str,
) -> Result<()> {
    let group_npub = keep_core::keys::bytes_to_npub(group_pubkey);
    out.newline();
    out.header("FROST Network Node");
    out.field("Group", &group_npub);
    out.field("Relay", relay);
    out.newline();

    let client = Client::new(beacon.clone());
    client
        .add_relay(relay)
        .await
        .map_err(|e| KeepError::runtime(format!("add relay: {e}")))?;
    client.connect().await;

    let nonce: [u8; 32] = keep_core::entropy::try_random_bytes()?;
    let event = keep_frost_net::KfpEventBuilder::duress_beacon(beacon, group_pubkey, &nonce)
        .map_err(|e| KeepError::runtime(format!("build duress beacon: {e}")))?;
    client
        .send_event(&event)
        .await
        .map_err(|e| KeepError::runtime(format!("publish duress beacon: {e}")))?;

    out.info("Starting FROST coordination node...");

    // Stay resident so the holder appears online but answers no evaluation
    // requests (fail-closed). Nothing here is duress-specific on screen.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
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
    fn ct_pubkey_eq_matches_std_eq() {
        let salt = [3u8; SALT_SIZE];
        let a = derive_beacon_key("x", &salt, P).unwrap().public_key();
        let b = derive_beacon_key("x", &salt, P).unwrap().public_key();
        let c = derive_beacon_key("y", &salt, P).unwrap().public_key();
        assert!(ct_pubkey_eq(&a, &b));
        assert!(!ct_pubkey_eq(&a, &c));
    }

    #[test]
    fn parse_duress_config_roundtrips_and_rejects_bad_input() {
        let salt = [5u8; SALT_SIZE];
        let npub = derive_beacon_key("dur", &salt, P)
            .unwrap()
            .public_key()
            .to_bech32()
            .unwrap();
        let salt_hex = hex::encode(salt);
        let (pk, parsed_salt) = parse_duress_config(&npub, &salt_hex).unwrap();
        assert_eq!(parsed_salt, salt);
        assert_eq!(pk.to_bech32().unwrap(), npub);
        // A too-short salt is rejected (not silently zero-padded).
        assert!(parse_duress_config(&npub, "00ff").is_err());
        // A non-npub pubkey is rejected.
        assert!(parse_duress_config("not-an-npub", &salt_hex).is_err());
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
