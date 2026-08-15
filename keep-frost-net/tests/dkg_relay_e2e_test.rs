// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! End-to-end DKG over a real relay websocket.
//!
//! The in-crate pipeline tests drive `DkgTransport` with a shared `Vec<Event>`,
//! which always replays every event ever published. A real relay does not: DKG
//! kinds are ephemeral, so the relay forwards them to *live* subscribers and
//! never stores them, and a later REQ returns EOSE with nothing. That is the
//! exact behavior the v1 transport got wrong, and a `Vec` cannot reproduce it.
//!
//! `MockRelay` implements the real rule (`local/inner.rs`: ephemeral kinds are
//! broadcast and returned early, never saved), so these tests exercise the
//! republish path against a relay that genuinely drops stored history.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use keep_core::frost::dkg::SoftwareDkgSession;
use keep_frost_net::dkg::{
    frost_group_id, run_software_dkg, ClientTransport, DkgPhase, DkgProgress, DkgRoster,
};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;

struct SilentProgress;

impl DkgProgress for SilentProgress {
    fn phase(&self, _phase: DkgPhase) {}
}

/// Per-group subkeys for `n` participants plus the roster they hash-bind to.
fn build_roster(n: u8, threshold: u8) -> (Vec<Keys>, DkgRoster) {
    let keys: Vec<Keys> = (0..n).map(|_| Keys::generate()).collect();
    let ordered: Vec<String> = keys
        .iter()
        .map(|k| k.public_key().to_bech32().expect("bech32"))
        .collect();
    let group_id = frost_group_id("dkg-relay-e2e", threshold, n, &ordered);
    let by_index: BTreeMap<u16, PublicKey> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i as u16 + 1, k.public_key()))
        .collect();
    (
        keys,
        DkgRoster {
            threshold,
            participants: n,
            by_index,
            group_id,
        },
    )
}

/// Drive one participant through a full DKG against `relay_url`.
async fn run_participant(
    relay_url: String,
    keys: Keys,
    roster: DkgRoster,
    group: String,
    our_index: u16,
    start_delay: Duration,
) -> keep_core::error::Result<[u8; 32]> {
    if !start_delay.is_zero() {
        tokio::time::sleep(start_delay).await;
    }

    let mut session = SoftwareDkgSession::init(
        roster.threshold as u16,
        roster.participants as u16,
        our_index,
    )?;
    let transport = ClientTransport::connect_hardened(&keys, &[relay_url], None).await?;
    let cancel = AtomicBool::new(false);

    let outcome = run_software_dkg(
        &mut session,
        &transport,
        &keys,
        &roster,
        &group,
        our_index,
        Duration::from_secs(40),
        &cancel,
        &SilentProgress,
    )
    .await;

    transport.disconnect().await;

    let outcome = outcome?;
    // The certificate must be complete for the roster, not merely observed
    // agreement: this is the CertEq property a timed-out peer relies on.
    outcome.certificate.verify(&roster)?;
    Ok(outcome.result.group_pubkey)
}

/// All three participants start together and must converge on one group key,
/// each holding a certificate that verifies against the shared roster.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_party_dkg_completes_over_a_real_relay() {
    let relay = MockRelay::run().await.expect("mock relay");
    let url = relay.url().await.to_string();
    let (keys, roster) = build_roster(3, 2);
    let group = hex::encode(roster.group_id);

    // `DkgTransport`/`DkgProgress` are not `Send`, so the runs cannot be
    // `tokio::spawn`ed; drive them concurrently on this task instead.
    let (a, b, c) = tokio::join!(
        run_participant(
            url.clone(),
            keys[0].clone(),
            roster.clone(),
            group.clone(),
            1,
            Duration::ZERO
        ),
        run_participant(
            url.clone(),
            keys[1].clone(),
            roster.clone(),
            group.clone(),
            2,
            Duration::ZERO
        ),
        run_participant(
            url.clone(),
            keys[2].clone(),
            roster.clone(),
            group.clone(),
            3,
            Duration::ZERO
        ),
    );

    let group_keys = [
        a.unwrap_or_else(|e| panic!("participant 1 failed: {e}")),
        b.unwrap_or_else(|e| panic!("participant 2 failed: {e}")),
        c.unwrap_or_else(|e| panic!("participant 3 failed: {e}")),
    ];

    assert!(
        group_keys.windows(2).all(|w| w[0] == w[1]),
        "participants disagreed on the group pubkey: {group_keys:?}"
    );
}

/// A participant that joins after the others have already published must still
/// complete. Ephemeral events are not stored, so this only passes if the
/// running peers rebuild and resend their round packages on each poll.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_joiner_is_not_starved_by_unstored_ephemeral_events() {
    let relay = MockRelay::run().await.expect("mock relay");
    let url = relay.url().await.to_string();
    let (keys, roster) = build_roster(3, 2);
    let group = hex::encode(roster.group_id);

    // Participant 3 starts well after 1 and 2 have published round 1, so the
    // relay has already forwarded and discarded those events.
    let (a, b, c) = tokio::join!(
        run_participant(
            url.clone(),
            keys[0].clone(),
            roster.clone(),
            group.clone(),
            1,
            Duration::ZERO
        ),
        run_participant(
            url.clone(),
            keys[1].clone(),
            roster.clone(),
            group.clone(),
            2,
            Duration::ZERO
        ),
        run_participant(
            url.clone(),
            keys[2].clone(),
            roster.clone(),
            group.clone(),
            3,
            Duration::from_millis(2_500)
        ),
    );

    let group_keys = [
        a.unwrap_or_else(|e| panic!("participant 1 failed: {e}")),
        b.unwrap_or_else(|e| panic!("participant 2 failed: {e}")),
        c.unwrap_or_else(|e| panic!("late joiner (participant 3) failed: {e}")),
    ];

    assert!(
        group_keys.windows(2).all(|w| w[0] == w[1]),
        "late joiner converged on a different group pubkey: {group_keys:?}"
    );
}
