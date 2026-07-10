// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Duress-mode keying and provisioning (coercion resistance, inc1b).
//!
//! A duress credential distinct from the vault password lets a coerced holder
//! fail closed and emit a signed duress beacon. This module derives the
//! dedicated beacon keypair from that credential and provisions it.

use std::path::Path;

use keep_core::crypto::{derive_key, Argon2Params, SALT_SIZE};
use keep_core::error::{KeepError, Result};
use keep_frost_net::DuressFreeze;
use nostr_sdk::prelude::*;
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use tracing::debug;

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
         values on `serve`. Treat the pinned pubkey as PROTECTED, not merely pinned: anyone who \
         learns it can grind the credential offline. Do NOT store the duress credential anywhere.",
    );
    Ok(())
}

/// Constant-time equality of two x-only pubkeys (via the workspace's `subtle`,
/// the same primitive used for CT comparisons elsewhere in the tree), so duress
/// detection does not leak by timing whether the entered password matched the
/// pinned beacon key.
fn ct_pubkey_eq(a: &PublicKey, b: &PublicKey) -> bool {
    a.to_bytes().ct_eq(&b.to_bytes()).into()
}

/// Spend the same KDF cost a genuine vault unlock would (the vault's own Argon2
/// params) and discard the result, so a duress start is wall-clock-
/// indistinguishable from a real unlock. The vault is NEVER unlocked here; this
/// only reproduces the missing second derivation that `keep.unlock` performs on
/// the normal path (the duress path returns before it). The derived key is held
/// in `keep_core`'s mlocked, drop-zeroized box.
pub(crate) fn equalize_unlock_cost(params: Argon2Params, salt: &[u8; SALT_SIZE]) -> Result<()> {
    let _ = derive_key(b"duress-unlock-cost-equalizer", salt, params)?;
    Ok(())
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

/// Build a single signed duress beacon event for `group_pubkey` with a fresh
/// random nonce. Split from the transport so the beacon's construction is unit-
/// testable without a live relay.
pub(crate) fn build_duress_event(beacon: &Keys, group_pubkey: &[u8; 32]) -> Result<Event> {
    let nonce: [u8; 32] = keep_core::entropy::try_random_bytes()?;
    keep_frost_net::KfpEventBuilder::duress_beacon(beacon, group_pubkey, &nonce)
        .map_err(|e| KeepError::runtime(format!("build beacon: {e}")))
}

/// How long to wait for the best-effort beacon publish before giving up and
/// staying resident, so a black-holed relay cannot hang the duress start.
const BEACON_PUBLISH_TIMEOUT_SECS: u64 = 10;

/// Parse the trusted duress-beacon pins (other holders' beacon npubs) that, when
/// one signs a received beacon, freeze THIS node. A malformed npub is fatal , the
/// operator meant to trust a specific key.
pub(crate) fn parse_beacon_pins(pins: &[String]) -> Result<Vec<PublicKey>> {
    pins.iter()
        .map(|p| {
            PublicKey::from_bech32(p.trim())
                .map_err(|e| KeepError::invalid_input(format!("--duress-beacon-pin {p}: {e}")))
        })
        .collect()
}

/// Read a persisted duress freeze at boot. `None` if the file is absent (normal:
/// not frozen). An existing but unparseable file is FATAL, not silently ignored:
/// a corrupt freeze marker must fail the node closed rather than let it resume
/// answering, which is the whole point of the sticky freeze.
pub(crate) fn read_persisted_freeze(path: &Path) -> Result<Option<DuressFreeze>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let freeze = serde_json::from_slice(&bytes).map_err(|e| {
                KeepError::invalid_input(format!(
                    "duress state file {} is present but unparseable ({e}); \
                     refusing to start un-frozen",
                    path.display()
                ))
            })?;
            Ok(Some(freeze))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KeepError::runtime(format!(
            "read duress state file {}: {e}",
            path.display()
        ))),
    }
}

/// The duress serve path: fail CLOSED (never unlock the vault or load the OPRF
/// share, so this holder answers no evaluations and the box drops below
/// threshold), best-effort publish ONE signed duress beacon, then stay resident
/// so the holder looks online but simply never answers. Reached only when the
/// entered password derived the pinned beacon key.
///
/// Beacon delivery is BEST-EFFORT and must never change observable behavior: a
/// coercer can black-hole the network, so a failed connect/publish neither aborts
/// nor prints anything (least of all the word "duress"). The box stays resident
/// and fail-closed regardless , the vault is already never unlocked.
///
/// The screen mirrors a normal serve start using data knowable without the vault
/// (group, relay). The `Share`/`Threshold`/`Attestation` lines a normal serve
/// derives from the unlocked share, and full on-wire indistinguishability of the
/// beacon, are the DOCUMENTED residuals (tracked with the inc2 wire-format
/// release gate). The load-bearing coercion property is that the box stays locked
/// , this fail-closed path plus the inc2 sticky freeze , invariant to which
/// password was entered.
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
    out.info("Starting FROST coordination node...");

    // Best-effort alert. Any failure is swallowed (logged only at debug, never on
    // screen and never mentioning duress) so the observable path is identical to
    // a normal start whose relay happens to be unreachable.
    let client = Client::new(beacon.clone());
    if client.add_relay(relay).await.is_ok() {
        client.connect().await;
        match build_duress_event(beacon, group_pubkey) {
            Ok(event) => {
                let send = tokio::time::timeout(
                    std::time::Duration::from_secs(BEACON_PUBLISH_TIMEOUT_SECS),
                    client.send_event(&event),
                )
                .await;
                if let Ok(Err(e)) = send {
                    debug!(error = %e, "beacon publish failed; staying resident");
                }
            }
            Err(e) => debug!(error = %e, "beacon build failed; staying resident"),
        }
    }

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
    fn build_duress_event_produces_a_verifiable_beacon() {
        let salt = [1u8; SALT_SIZE];
        let beacon = derive_beacon_key("the-duress-word", &salt, P).unwrap();
        let group = [42u8; 32];
        let event = build_duress_event(&beacon, &group).unwrap();
        // The beacon verifies against the beacon pubkey and the expected group.
        keep_frost_net::verify_duress_beacon(&event, &beacon.public_key(), &group, 3600)
            .expect("freshly built beacon must verify");
        // Two builds use fresh nonces, so their events differ (replay-distinct).
        let again = build_duress_event(&beacon, &group).unwrap();
        assert_ne!(event.id, again.id);
    }

    #[test]
    fn parse_beacon_pins_parses_and_rejects() {
        let k = Keys::generate();
        let npub = k.public_key().to_bech32().unwrap();
        assert_eq!(parse_beacon_pins(&[npub]).unwrap(), vec![k.public_key()]);
        assert!(parse_beacon_pins(&["not-an-npub".to_string()]).is_err());
    }

    #[test]
    fn read_persisted_freeze_roundtrips_and_fails_closed_on_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("duress.state");
        // Absent -> None (not frozen).
        assert!(read_persisted_freeze(&path).unwrap().is_none());
        // A valid persisted freeze round-trips.
        let f = DuressFreeze {
            beacon_pubkey: Keys::generate().public_key(),
            nonce: [3u8; 32],
            created_at: 99,
        };
        std::fs::write(&path, serde_json::to_vec(&f).unwrap()).unwrap();
        let got = read_persisted_freeze(&path).unwrap().unwrap();
        assert_eq!(got.created_at, 99);
        assert_eq!(got.nonce, [3u8; 32]);
        // A present-but-corrupt file fails closed (Err), never silently un-frozen.
        std::fs::write(&path, b"garbage").unwrap();
        assert!(read_persisted_freeze(&path).is_err());
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
