// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Duress-mode keying and provisioning (coercion resistance, inc1b).
//!
//! A duress credential distinct from the vault password lets a coerced holder
//! fail closed and emit a signed duress beacon. This module derives the
//! dedicated beacon keypair from that credential and provisions it.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Interval between duress-beacon re-broadcasts. The beacon is re-published (with
/// a fresh nonce) on this cadence so a holder that was offline, reconnecting, or
/// slow to subscribe when the first one fired still receives one and freezes.
const BEACON_REPUBLISH_INTERVAL_SECS: u64 = 30;

/// Default delay before a `duress-clear --initiate` may be executed: a generous
/// window for out-of-band intervention (`--cancel`) if the clear was coerced.
pub const DEFAULT_DURESS_CLEAR_DELAY_SECS: u64 = 24 * 60 * 60;

/// Non-overridable floor on the clear delay. The cancelable window is the whole
/// point of the delayed clear, so `--delay-secs` cannot dial it below this and
/// nullify the ability to intervene.
pub const MIN_DURESS_CLEAR_DELAY_SECS: u64 = 60 * 60;

/// A pending, delayed operator clear (Argent guardian-recovery pattern): the box
/// stays frozen until `--execute` runs after `requested_at + delay_secs`, and any
/// operator can `--cancel` during the window. `freeze_nonce` binds the clear to
/// the SPECIFIC freeze it was armed against, so a clear armed during one freeze
/// cannot lift a later, different freeze the operator never reviewed.
#[derive(serde::Serialize, serde::Deserialize)]
struct ClearPending {
    requested_at: u64,
    delay_secs: u64,
    freeze_nonce: [u8; 32],
}

/// Wall-clock unix seconds. Fails CLOSED (an `Err`, not a silent 0) so arming a
/// clear against a broken clock cannot later pass the delay gate the moment the
/// clock is fixed. NOTE: `execute` trusts this local wall clock; a forward clock
/// jump (manual or loose NTP) collapses the delay. That is acceptable only under
/// the documented boundary , the state directory is root-owned and not
/// operator-writable, so the same party that could step the clock could also just
/// delete the freeze file directly.
fn now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| KeepError::runtime(format!("system clock is before the UNIX epoch: {e}")))
}

/// The pending-clear marker lives beside the freeze state file.
fn clear_marker_path(state_file: &Path) -> PathBuf {
    let mut p = state_file.as_os_str().to_owned();
    p.push(".clear-pending");
    PathBuf::from(p)
}

/// `keep frost network duress-clear`: lift a sticky duress freeze via a delayed,
/// cancelable operator action. Actions: `initiate` (start the delay; box stays
/// frozen), `cancel` (abort the window), `execute` (lift the freeze once the delay
/// elapses). `serve` is unchanged; the marker is consulted only here.
///
/// SCOPE / boundary: the delay defends only the CLI-confined coercion case , an
/// operator who is socially/remotely coerced but confined to running the
/// sanctioned CLI. It is NOT a control against a party with write access to the
/// state directory: such a party can forge the marker OR simply delete the freeze
/// file directly (the same capability), bypassing the delay entirely. The real
/// security boundary is filesystem permissions: the state directory MUST be
/// root-owned and not operator-writable (see the `--duress-state-file` warning).
pub fn cmd_frost_network_duress_clear(
    out: &Output,
    state_file: &Path,
    action: crate::cli::DuressClearAction,
    delay_secs: u64,
) -> Result<()> {
    use crate::cli::DuressClearAction::*;
    let now = now_secs()?;
    match action {
        Initiate => {
            clear_initiate(state_file, delay_secs, now)?;
            out.warn(&format!(
                "Duress clear INITIATED. The box stays FROZEN for {delay_secs}s, then run \
                 `duress-clear ... execute`. Cancel any time with `duress-clear ... cancel`."
            ));
        }
        Cancel => {
            if clear_cancel(state_file)? {
                out.info("Pending duress clear cancelled; the box remains frozen.");
            } else {
                out.info("No pending duress clear to cancel.");
            }
        }
        Execute => {
            clear_execute(state_file, now)?;
            out.info(
                "Duress freeze CLEARED. Restart `serve` (or reboot) to resume normal operation.",
            );
        }
    }
    Ok(())
}

/// Arm a delayed clear. Enforces the non-overridable delay floor, requires an
/// active freeze (refuse to arm against nothing), and binds the marker to that
/// freeze's `nonce` so it can only ever clear THIS freeze, not a later one.
fn clear_initiate(state_file: &Path, delay_secs: u64, now: u64) -> Result<()> {
    if delay_secs < MIN_DURESS_CLEAR_DELAY_SECS {
        return Err(KeepError::invalid_input(format!(
            "--delay-secs must be at least {MIN_DURESS_CLEAR_DELAY_SECS}s: the cancelable window is \
             the point of the delayed clear and cannot be dialed to zero"
        )));
    }
    let freeze = read_persisted_freeze(state_file)?.ok_or_else(|| {
        KeepError::invalid_input(format!(
            "no duress freeze at {}: nothing to clear",
            state_file.display()
        ))
    })?;
    let pending = ClearPending {
        requested_at: now,
        delay_secs,
        freeze_nonce: freeze.nonce,
    };
    let bytes = serde_json::to_vec(&pending)
        .map_err(|e| KeepError::runtime(format!("serialize clear marker: {e}")))?;
    // Non-atomic + default perms is acceptable: the marker carries no secret, a
    // torn write fails `execute` closed (unparseable -> error, box stays frozen),
    // and the state dir's permissions are the real boundary.
    let marker = clear_marker_path(state_file);
    std::fs::write(&marker, &bytes)
        .map_err(|e| KeepError::runtime(format!("write {}: {e}", marker.display())))
}

/// Abort a pending clear. Returns whether a marker was actually present.
fn clear_cancel(state_file: &Path) -> Result<bool> {
    match std::fs::remove_file(clear_marker_path(state_file)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(KeepError::runtime(format!("remove clear marker: {e}"))),
    }
}

/// Execute a pending clear if its delay has elapsed by `now` AND the currently
/// active freeze is the same one the clear was armed against. Removes the freeze
/// state file (absent = not frozen) and the marker. A running `serve` stays frozen
/// until restarted. Errors if no clear is pending, the freeze changed, or the
/// delay has not elapsed.
fn clear_execute(state_file: &Path, now: u64) -> Result<()> {
    let marker = clear_marker_path(state_file);
    let pending: ClearPending = match std::fs::read(&marker) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            KeepError::invalid_input(format!(
                "clear marker {} unparseable: {e}",
                marker.display()
            ))
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeepError::invalid_input(
                "no pending duress clear; run `duress-clear ... initiate` first",
            ));
        }
        Err(e) => {
            return Err(KeepError::runtime(format!(
                "read {}: {e}",
                marker.display()
            )))
        }
    };
    // Bind to the freeze: only clear the exact freeze this was armed against. A
    // NEW duress event during the window overwrites the state file with a fresh
    // nonce, so a stale pending clear (or a leftover marker) can never lift it ,
    // that freeze needs its own initiate + cancel window.
    match read_persisted_freeze(state_file)? {
        Some(freeze) if freeze.nonce == pending.freeze_nonce => {}
        Some(_) => {
            return Err(KeepError::invalid_input(
                "the active duress freeze changed since this clear was initiated; \
                 re-initiate to review and clear the current freeze",
            ));
        }
        None => {
            // Already un-frozen; drop the now-meaningless marker.
            let _ = std::fs::remove_file(&marker);
            return Err(KeepError::invalid_input(
                "no active duress freeze; nothing to clear",
            ));
        }
    }
    let ready_at = pending.requested_at.saturating_add(pending.delay_secs);
    if now < ready_at {
        return Err(KeepError::invalid_input(format!(
            "clear delay not elapsed; {}s remaining. Cancel with `duress-clear ... cancel`.",
            ready_at - now
        )));
    }
    if let Err(e) = std::fs::remove_file(state_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(KeepError::runtime(format!(
                "remove {}: {e}",
                state_file.display()
            )));
        }
    }
    // A leftover marker is harmless now: it is bound to this freeze's nonce, which
    // no longer exists, so it can never match a future freeze.
    let _ = std::fs::remove_file(&marker);
    Ok(())
}

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
        // Re-broadcast the beacon on an interval (fresh nonce each time), not once:
        // a one-shot alert would miss any holder that is briefly offline,
        // reconnecting, or slow to subscribe when it fires. Holders freeze on the
        // first one they verify and short-circuit the rest, so the repeat is
        // idempotent for them. This loop also keeps the process resident so the
        // holder looks online but answers no evaluations (fail-closed).
        //
        // connect() returns immediately, so we RE-CHECK the connection each pass
        // rather than gating on a single fixed window: on a slow or contended host
        // the WebSocket + NIP-42 handshake can take longer than any one timeout,
        // and a one-shot give-up would leave the box resident but silent (no holder
        // ever freezes , a coerced holder on a slow box would fail to alert). We
        // only build+send once a relay is Connected; otherwise poll briefly and
        // retry, which also recovers if the connection later drops. The send itself
        // may still race NIP-42 auth (Connected != Authenticated); the interval
        // retry covers a rejected first publish. RELEASE GATE: the fixed cadence is
        // itself a relay-observable duress signature (distinct from the wire FORMAT
        // gate); traffic-shape indistinguishability is part of that gate.
        loop {
            let connected = client
                .relays()
                .await
                .values()
                .any(|r| matches!(r.status(), RelayStatus::Connected));
            if !connected {
                // Not connected yet (or dropped); check again shortly.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            match build_duress_event(beacon, group_pubkey) {
                Ok(event) => {
                    let send = tokio::time::timeout(
                        std::time::Duration::from_secs(BEACON_PUBLISH_TIMEOUT_SECS),
                        client.send_event(&event),
                    )
                    .await;
                    match send {
                        Ok(Ok(output)) => debug!(
                            id = %output.id(),
                            success = output.success.len(),
                            failed = output.failed.len(),
                            "beacon published"
                        ),
                        Ok(Err(e)) => debug!(error = %e, "beacon publish failed"),
                        Err(_) => debug!("beacon publish timed out"),
                    }
                }
                Err(e) => debug!(error = %e, "beacon build failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                BEACON_REPUBLISH_INTERVAL_SECS,
            ))
            .await;
        }
    }

    // Reached only when the relay could not be added/connected: stay resident so
    // the holder appears online but answers no evaluation requests (fail-closed).
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

    fn write_freeze_nonce(path: &Path, nonce: [u8; 32]) {
        let f = DuressFreeze {
            beacon_pubkey: Keys::generate().public_key(),
            nonce,
            created_at: 10,
        };
        std::fs::write(path, serde_json::to_vec(&f).unwrap()).unwrap();
    }
    fn write_freeze(path: &Path) {
        write_freeze_nonce(path, [1u8; 32]);
    }

    // A delay comfortably above the floor, used as a fixed value in tests.
    const TEST_DELAY: u64 = 2 * MIN_DURESS_CLEAR_DELAY_SECS;

    #[test]
    fn clear_initiate_requires_an_active_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.state");
        // No freeze -> initiate refuses.
        assert!(clear_initiate(&path, TEST_DELAY, 1000).is_err());
        write_freeze(&path);
        clear_initiate(&path, TEST_DELAY, 1000).unwrap();
        assert!(clear_marker_path(&path).exists(), "marker must be written");
    }

    #[test]
    fn clear_initiate_rejects_delay_below_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.state");
        write_freeze(&path);
        // 0 (or anything below the floor) is refused: the window cannot be nulled.
        assert!(clear_initiate(&path, 0, 1000).is_err());
        assert!(clear_initiate(&path, MIN_DURESS_CLEAR_DELAY_SECS - 1, 1000).is_err());
        clear_initiate(&path, MIN_DURESS_CLEAR_DELAY_SECS, 1000).unwrap();
    }

    #[test]
    fn clear_execute_gated_by_delay_then_lifts_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.state");
        write_freeze(&path);
        // Execute with no pending clear -> error.
        assert!(clear_execute(&path, 1000).is_err());
        // Initiate at t=1000; ready at 1000 + TEST_DELAY.
        clear_initiate(&path, TEST_DELAY, 1000).unwrap();
        let ready = 1000 + TEST_DELAY;
        // Before the delay elapses -> refused, freeze intact.
        assert!(clear_execute(&path, ready - 1).is_err());
        assert!(path.exists(), "freeze file must remain while gated");
        // At/after the delay -> clears the freeze file and the marker.
        clear_execute(&path, ready).unwrap();
        assert!(!path.exists(), "freeze file must be removed");
        assert!(!clear_marker_path(&path).exists(), "marker must be removed");
    }

    #[test]
    fn clear_execute_refuses_when_the_freeze_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.state");
        write_freeze_nonce(&path, [1u8; 32]);
        clear_initiate(&path, TEST_DELAY, 1000).unwrap();
        // A NEW duress event overwrites the freeze during the window.
        write_freeze_nonce(&path, [2u8; 32]);
        // Even well past the delay, execute refuses: the clear was armed against a
        // different freeze, so the fresh one is NOT lifted.
        assert!(clear_execute(&path, 1000 + TEST_DELAY + 10_000).is_err());
        assert!(
            path.exists(),
            "a stale clear must not lift a newer, different freeze"
        );
    }

    #[test]
    fn clear_cancel_aborts_a_pending_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.state");
        write_freeze(&path);
        assert!(!clear_cancel(&path).unwrap(), "no marker yet");
        clear_initiate(&path, TEST_DELAY, 1000).unwrap();
        assert!(clear_cancel(&path).unwrap(), "marker existed");
        // After cancel, execute is refused (no pending clear) and freeze intact.
        assert!(clear_execute(&path, 10_000_000).is_err());
        assert!(path.exists(), "freeze must survive a cancelled clear");
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
