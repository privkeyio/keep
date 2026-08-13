// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Relay-driven transport for on-device DKG group creation.
//!
//! The crypto steps live in [`crate::dkg::DkgSession`] (FROST `part1`/`part2`/
//! `part3`); this module moves the packages those steps produce between the
//! participants' devices over nostr relays, so a group can be created without
//! any device ever holding the whole key.
//!
//! ## Bootstrap
//!
//! DKG runs *before* a group key exists, so it cannot key its transport off the
//! group pubkey the way [`keep_frost_net`] does for signing. Instead every
//! participant of one run shares a single 32-byte `session_secret` out of band
//! (a scanned QR at setup). From it, by domain-separated SHA-256, we derive:
//!
//! - a public **channel id** ([`derive_channel`]) placed in the `d` tag, which
//!   is all a relay sees of the run; and
//! - each participant's **ephemeral relay identity** ([`derive_dkg_keys`]),
//!   deterministic in the participant index so every device can compute every
//!   other device's pubkey — used to address round-2 packages and to
//!   authenticate senders.
//!
//! The secret never crosses a relay. An event tagged for this run is accepted
//! only when its author key equals the identity derived for the index it claims,
//! so a party without the secret cannot inject or spoof packages.
//!
//! ## Flow
//!
//! 1. round-1 package broadcast (plaintext; round-1 packages are public) and
//!    collected from the other `participants - 1` devices;
//! 2. `part2` run locally, producing one round-2 package per recipient, each
//!    NIP-44-encrypted to that recipient's derived pubkey and published;
//! 3. the round-2 packages addressed to us collected and fed to `part3`, which
//!    yields this device's share.
//!
//! Our own package is re-published on every poll so a peer that connects late
//! still receives it (relays forward ephemeral events only to live subscribers).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use keep_core::relay::TIMESTAMP_TWEAK_RANGE;

use crate::dkg::{DkgResult, DkgRound1Package, DkgRound2Package, DkgSession};
use crate::error::KeepMobileError;
use crate::types::{DkgConfig, DkgProgressUpdate};

/// Ephemeral nostr kind (20000–29999) carrying DKG packages. Shares the kind the
/// signing protocol uses so relays that forward one forward the other, but is
/// disambiguated by the `d` (channel) and `t` (round) tags — never the `g` tag a
/// signing node filters on, so no live node ever sees these events.
const DKG_EVENT_KIND: u16 = 24242;

const DKG_CHANNEL_DOMAIN: &[u8] = b"keep-frost-dkg-channel-v1";
const DKG_IDENTITY_DOMAIN: &[u8] = b"keep-frost-dkg-identity-v1";

const ROUND1_TAG: &str = "dkg1";
const ROUND2_TAG: &str = "dkg2";

/// How long each `fetch_events` poll blocks waiting for new packages before we
/// re-publish ours and poll again. Short so a late peer is served promptly.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Upper bound on an encrypted round-2 payload we will attempt to decrypt, so a
/// malicious relay cannot feed us an unbounded body. A round-2 package is a few
/// hundred bytes; hex + JSON + NIP-44 overhead stays well under this.
const MAX_WIRE_CONTENT: usize = 64 * 1024;

/// Reports DKG progress to the native layer. Implemented on the foreign side
/// (Kotlin) so setup UI can render live state without polling. Called from the
/// runtime thread; implementations must be non-blocking.
#[uniffi::export(with_foreign)]
pub trait DkgProgressCallback: Send + Sync {
    fn on_progress(&self, update: DkgProgressUpdate);
}

/// One DKG package on the wire: the sender's participant index and the
/// hex-encoded FROST package bytes. For round 2 the whole JSON is NIP-44
/// encrypted to the recipient; for round 1 it is plaintext.
#[derive(Serialize, Deserialize)]
struct DkgWire {
    i: u16,
    pkg: String,
}

/// Public per-run coordination channel derived from the shared secret. Placed in
/// the `d` tag; a relay learns only this, not the secret.
fn derive_channel(secret: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DKG_CHANNEL_DOMAIN);
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

/// Deterministic relay identity for `index` in this run. Every participant can
/// compute this for every index, which is what lets round-2 packages be
/// addressed and senders authenticated.
fn derive_dkg_keys(secret: &[u8; 32], index: u16) -> Result<Keys, KeepMobileError> {
    let mut hasher = Sha256::new();
    hasher.update(DKG_IDENTITY_DOMAIN);
    hasher.update(secret);
    hasher.update(index.to_be_bytes());
    let derived: [u8; 32] = hasher.finalize().into();
    let secret_key = SecretKey::from_slice(&derived).map_err(|e| KeepMobileError::FrostError {
        msg: format!("Failed to derive DKG identity: {e}"),
    })?;
    Ok(Keys::new(secret_key))
}

fn parse_secret(hex_secret: &str) -> Result<[u8; 32], KeepMobileError> {
    let bytes = hex::decode(hex_secret).map_err(|_| KeepMobileError::InvalidInput {
        msg: "session_secret must be hex".into(),
    })?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeepMobileError::InvalidInput {
            msg: "session_secret must be 32 bytes".into(),
        })
}

/// Run a full relay-driven DKG and return this device's share export. The
/// session's crypto state is driven through `session`; transport is a dedicated,
/// short-lived client keyed by the bootstrap identity (no stored share needed).
///
/// `overall_timeout` bounds the whole run; each round independently must
/// complete within it or the run fails with [`KeepMobileError::Timeout`].
pub async fn run_dkg(
    session: &DkgSession,
    config: DkgConfig,
    name: &str,
    passphrase: &str,
    overall_timeout: Duration,
    progress: Arc<dyn DkgProgressCallback>,
) -> Result<DkgResult, KeepMobileError> {
    let result = run_dkg_inner(
        session,
        config,
        name,
        passphrase,
        overall_timeout,
        &progress,
    )
    .await;
    match &result {
        Ok(r) => progress.on_progress(DkgProgressUpdate::Complete {
            group_pubkey: r.group_pubkey.clone(),
        }),
        Err(e) => {
            session.reset().await;
            progress.on_progress(DkgProgressUpdate::Failed {
                reason: e.to_string(),
            });
        }
    }
    result
}

async fn run_dkg_inner(
    session: &DkgSession,
    config: DkgConfig,
    name: &str,
    passphrase: &str,
    overall_timeout: Duration,
    progress: &Arc<dyn DkgProgressCallback>,
) -> Result<DkgResult, KeepMobileError> {
    let secret = parse_secret(&config.session_secret)?;
    let channel = derive_channel(&secret);
    let our_index = config.our_index;
    let our_keys = derive_dkg_keys(&secret, our_index)?;
    let peer_count = config.participants.saturating_sub(1) as usize;

    progress.on_progress(DkgProgressUpdate::Connecting);

    // Start the crypto session first: it validates the config (threshold,
    // participant count, our index, relay URLs) before we touch the network.
    let our_round1 = session.start(config.clone()).await?;

    let client = connect(&our_keys, &config.relays).await?;
    let since = Timestamp::from(Timestamp::now().as_secs().saturating_sub(60));

    // Round 1: broadcast ours, collect peers'.
    let our_round1_event = round1_event(&our_keys, &channel, our_index, &our_round1.package_bytes)?;
    let round1_filter = Filter::new()
        .kind(Kind::Custom(DKG_EVENT_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), channel.clone())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::T), ROUND1_TAG)
        .since(since);

    let round1_packages = collect(
        &client,
        &our_round1_event,
        round1_filter,
        peer_count,
        overall_timeout,
        |received| DkgProgressUpdate::Round1 {
            received,
            total: config.participants - 1,
        },
        progress,
        |event| decode_round1(&secret, config.participants, our_index, event),
    )
    .await?;

    let round2_out = session.receive_round1_packages(round1_packages).await?;

    // Round 2: publish one encrypted package per recipient, collect ours.
    let mut our_round2_events = Vec::with_capacity(round2_out.len());
    for pkg in &round2_out {
        let recipient = derive_dkg_keys(&secret, pkg.recipient_index)?.public_key();
        our_round2_events.push(round2_event(
            &our_keys,
            &recipient,
            &channel,
            our_index,
            &pkg.package_bytes,
        )?);
    }

    let round2_filter = Filter::new()
        .kind(Kind::Custom(DKG_EVENT_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), channel.clone())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::T), ROUND2_TAG)
        .pubkey(our_keys.public_key())
        .since(since);

    let round2_packages = collect_many(
        &client,
        &our_round2_events,
        round2_filter,
        peer_count,
        overall_timeout,
        |received| DkgProgressUpdate::Round2 {
            received,
            total: config.participants - 1,
        },
        progress,
        |event| decode_round2(&secret, &our_keys, config.participants, our_index, event),
    )
    .await?;

    progress.on_progress(DkgProgressUpdate::Finalizing);
    let result = session
        .receive_round2_packages(round2_packages, name, passphrase)
        .await;

    client.disconnect().await;
    result
}

async fn connect(keys: &Keys, relays: &[String]) -> Result<Client, KeepMobileError> {
    let client = Client::new(keys.clone());
    for relay in relays {
        client
            .pool()
            .add_relay(relay, RelayOptions::default())
            .await
            .map_err(|e| KeepMobileError::NetworkError {
                msg: format!("Failed to add relay {relay}: {e}"),
            })?;
    }
    client.connect().await;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let any_connected = client
                .relays()
                .await
                .values()
                .any(|r| matches!(r.status(), RelayStatus::Connected));
            if any_connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| KeepMobileError::NetworkError {
        msg: "Timed out connecting to relays".into(),
    })?;

    Ok(client)
}

fn round1_event(
    keys: &Keys,
    channel: &str,
    our_index: u16,
    package_bytes: &[u8],
) -> Result<Event, KeepMobileError> {
    let content = serde_json::to_string(&DkgWire {
        i: our_index,
        pkg: hex::encode(package_bytes),
    })
    .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;

    EventBuilder::new(Kind::Custom(DKG_EVENT_KIND), content)
        .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
        .tag(Tag::custom(TagKind::custom("d"), [channel.to_string()]))
        .tag(Tag::custom(TagKind::custom("t"), [ROUND1_TAG.to_string()]))
        .sign_with_keys(keys)
        .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })
}

fn round2_event(
    keys: &Keys,
    recipient: &PublicKey,
    channel: &str,
    our_index: u16,
    package_bytes: &[u8],
) -> Result<Event, KeepMobileError> {
    let content = serde_json::to_string(&DkgWire {
        i: our_index,
        pkg: hex::encode(package_bytes),
    })
    .map_err(|e| KeepMobileError::Serialization { msg: e.to_string() })?;
    let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
        .map_err(|e| KeepMobileError::FrostError {
            msg: format!("Failed to encrypt round 2 package: {e}"),
        })?;

    EventBuilder::new(Kind::Custom(DKG_EVENT_KIND), encrypted)
        .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
        .tag(Tag::public_key(*recipient))
        .tag(Tag::custom(TagKind::custom("d"), [channel.to_string()]))
        .tag(Tag::custom(TagKind::custom("t"), [ROUND2_TAG.to_string()]))
        .sign_with_keys(keys)
        .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })
}

/// Authenticate `event` as coming from the participant it claims to be, and
/// return that claimed index. `None` (with the event dropped) if the author key
/// does not match the identity derived for the claimed index, if the index is
/// out of range, or if it is our own — anything a well-behaved peer would not
/// send.
fn authenticated_index(
    secret: &[u8; 32],
    participants: u16,
    our_index: u16,
    claimed: u16,
    event: &Event,
) -> Option<u16> {
    if claimed == our_index || claimed < 1 || claimed > participants {
        return None;
    }
    let expected = derive_dkg_keys(secret, claimed).ok()?.public_key();
    if event.pubkey != expected {
        return None;
    }
    Some(claimed)
}

fn decode_round1(
    secret: &[u8; 32],
    participants: u16,
    our_index: u16,
    event: &Event,
) -> Option<(u16, DkgRound1Package)> {
    if event.content.len() > MAX_WIRE_CONTENT {
        return None;
    }
    let wire: DkgWire = serde_json::from_str(&event.content).ok()?;
    let index = authenticated_index(secret, participants, our_index, wire.i, event)?;
    let package_bytes = hex::decode(&wire.pkg).ok()?;
    Some((
        index,
        DkgRound1Package {
            participant_index: index,
            package_bytes,
        },
    ))
}

fn decode_round2(
    secret: &[u8; 32],
    our_keys: &Keys,
    participants: u16,
    our_index: u16,
    event: &Event,
) -> Option<(u16, DkgRound2Package)> {
    if event.content.len() > MAX_WIRE_CONTENT {
        return None;
    }
    let plaintext = nip44::decrypt(our_keys.secret_key(), &event.pubkey, &event.content).ok()?;
    let wire: DkgWire = serde_json::from_str(&plaintext).ok()?;
    let index = authenticated_index(secret, participants, our_index, wire.i, event)?;
    let package_bytes = hex::decode(&wire.pkg).ok()?;
    Some((
        index,
        DkgRound2Package {
            sender_index: index,
            recipient_index: our_index,
            package_bytes,
        },
    ))
}

/// Poll `filter` until `expected` distinct peers' packages arrive, re-publishing
/// `ours` each round so late peers are served. `decode` both authenticates an
/// event and turns it into a `(sender_index, package)`; duplicates by sender are
/// ignored. Fails with [`KeepMobileError::Timeout`] past `deadline`.
#[allow(clippy::too_many_arguments)]
async fn collect<T>(
    client: &Client,
    ours: &Event,
    filter: Filter,
    expected: usize,
    overall_timeout: Duration,
    mut progress_for: impl FnMut(u16) -> DkgProgressUpdate,
    progress: &Arc<dyn DkgProgressCallback>,
    decode: impl Fn(&Event) -> Option<(u16, T)>,
) -> Result<Vec<T>, KeepMobileError> {
    collect_many(
        client,
        std::slice::from_ref(ours),
        filter,
        expected,
        overall_timeout,
        &mut progress_for,
        progress,
        decode,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn collect_many<T>(
    client: &Client,
    ours: &[Event],
    filter: Filter,
    expected: usize,
    overall_timeout: Duration,
    mut progress_for: impl FnMut(u16) -> DkgProgressUpdate,
    progress: &Arc<dyn DkgProgressCallback>,
    decode: impl Fn(&Event) -> Option<(u16, T)>,
) -> Result<Vec<T>, KeepMobileError> {
    let mut collected: BTreeMap<u16, T> = BTreeMap::new();
    progress.on_progress(progress_for(0));

    let outcome = tokio::time::timeout(overall_timeout, async {
        loop {
            for ev in ours {
                let _ = client.send_event(ev).await;
            }
            if expected == 0 {
                return Ok(());
            }

            let events = client
                .fetch_events(filter.clone(), POLL_INTERVAL)
                .await
                .map_err(|e| KeepMobileError::NetworkError { msg: e.to_string() })?;

            let before = collected.len();
            for event in events {
                if let Some((index, package)) = decode(&event) {
                    collected.entry(index).or_insert(package);
                }
            }
            if collected.len() != before {
                progress.on_progress(progress_for(collected.len() as u16));
            }
            if collected.len() >= expected {
                return Ok(());
            }
        }
    })
    .await;

    match outcome {
        Ok(Ok(())) => Ok(collected.into_values().collect()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(KeepMobileError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        [7u8; 32]
    }

    fn config(index: u16) -> DkgConfig {
        DkgConfig {
            group_name: "test".into(),
            threshold: 2,
            participants: 3,
            our_index: index,
            relays: vec!["wss://relay.example.com".into()],
            session_secret: hex::encode(secret()),
        }
    }

    #[test]
    fn channel_is_deterministic_and_hides_secret() {
        let s = secret();
        assert_eq!(derive_channel(&s), derive_channel(&s));
        assert_ne!(derive_channel(&s), hex::encode(s));
        assert_ne!(derive_channel(&s), derive_channel(&[8u8; 32]));
    }

    #[test]
    fn identities_are_deterministic_and_distinct_per_index() {
        let s = secret();
        let a = derive_dkg_keys(&s, 1).unwrap().public_key();
        let b = derive_dkg_keys(&s, 2).unwrap().public_key();
        assert_eq!(a, derive_dkg_keys(&s, 1).unwrap().public_key());
        assert_ne!(a, b);
        // A different secret yields a different identity for the same index.
        assert_ne!(a, derive_dkg_keys(&[8u8; 32], 1).unwrap().public_key());
    }

    #[test]
    fn round1_rejects_spoofed_or_out_of_range_sender() {
        let s = secret();
        // Peer 2's real event authenticates as index 2 to peer 1.
        let keys2 = derive_dkg_keys(&s, 2).unwrap();
        let ev = round1_event(&keys2, &derive_channel(&s), 2, b"pkgbytes").unwrap();
        assert!(decode_round1(&s, 3, 1, &ev).is_some());
        // Our own index is dropped (we already hold our package).
        assert!(decode_round1(&s, 3, 2, &ev).is_none());

        // An outsider (key not derived from the secret) claiming index 2 is rejected.
        let outsider = Keys::generate();
        let forged = round1_event(&outsider, &derive_channel(&s), 2, b"pkgbytes").unwrap();
        assert!(decode_round1(&s, 3, 1, &forged).is_none());

        // A participant spoofing a different index than its key is rejected.
        let spoof = round1_event(&keys2, &derive_channel(&s), 3, b"pkgbytes").unwrap();
        assert!(decode_round1(&s, 3, 1, &spoof).is_none());

        // Out-of-range index is rejected.
        let oor = round1_event(&keys2, &derive_channel(&s), 99, b"pkgbytes").unwrap();
        assert!(decode_round1(&s, 3, 1, &oor).is_none());
    }

    #[test]
    fn round2_roundtrips_only_to_addressed_recipient() {
        let s = secret();
        let sender = derive_dkg_keys(&s, 1).unwrap();
        let recipient_keys = derive_dkg_keys(&s, 2).unwrap();
        let ev = round2_event(
            &sender,
            &recipient_keys.public_key(),
            &derive_channel(&s),
            1,
            b"secretshare",
        )
        .unwrap();

        let decoded = decode_round2(&s, &recipient_keys, 3, 2, &ev).unwrap();
        assert_eq!(decoded.0, 1);
        assert_eq!(decoded.1.sender_index, 1);
        assert_eq!(decoded.1.recipient_index, 2);
        assert_eq!(decoded.1.package_bytes, b"secretshare");

        // A different participant cannot decrypt a package addressed elsewhere.
        let wrong = derive_dkg_keys(&s, 3).unwrap();
        assert!(decode_round2(&s, &wrong, 3, 3, &ev).is_none());
    }

    /// Drives a real 2-of-3 DKG through the full wire encode/decode/authenticate
    /// pipeline, exchanging packages in memory (no relay Client). Proves the
    /// transport layer's serialization and authentication are consistent with the
    /// crypto and that all three participants converge on one group key.
    #[tokio::test]
    async fn full_2of3_dkg_over_wire_pipeline() {
        let s = secret();
        let channel = derive_channel(&s);
        let indices = [1u16, 2, 3];

        let sessions: Vec<DkgSession> = indices.iter().map(|_| DkgSession::new()).collect();
        let keys: Vec<Keys> = indices
            .iter()
            .map(|i| derive_dkg_keys(&s, *i).unwrap())
            .collect();

        // Round 1: each starts and publishes its package as a signed event.
        let mut round1_events = Vec::new();
        for (n, &i) in indices.iter().enumerate() {
            let r1 = sessions[n].start(config(i)).await.unwrap();
            round1_events.push(round1_event(&keys[n], &channel, i, &r1.package_bytes).unwrap());
        }

        // Each collects the others' round-1 packages and runs part2.
        let mut round2_events: Vec<Event> = Vec::new();
        for (n, &i) in indices.iter().enumerate() {
            let incoming: Vec<DkgRound1Package> = round1_events
                .iter()
                .filter_map(|ev| decode_round1(&s, 3, i, ev).map(|(_, p)| p))
                .collect();
            assert_eq!(incoming.len(), 2);
            let out = sessions[n].receive_round1_packages(incoming).await.unwrap();
            for pkg in &out {
                let recipient = derive_dkg_keys(&s, pkg.recipient_index)
                    .unwrap()
                    .public_key();
                round2_events.push(
                    round2_event(&keys[n], &recipient, &channel, i, &pkg.package_bytes).unwrap(),
                );
            }
        }

        // Each collects the round-2 packages addressed to it and finalizes.
        let mut group_pubkeys = Vec::new();
        for (n, &i) in indices.iter().enumerate() {
            let incoming: Vec<DkgRound2Package> = round2_events
                .iter()
                .filter_map(|ev| decode_round2(&s, &keys[n], 3, i, ev).map(|(_, p)| p))
                .collect();
            assert_eq!(incoming.len(), 2);
            let result = sessions[n]
                .receive_round2_packages(incoming, "test", "passphrase")
                .await
                .unwrap();
            group_pubkeys.push(result.group_pubkey);
        }

        // No device held the whole key, yet all three agree on the group pubkey.
        assert_eq!(group_pubkeys[0], group_pubkeys[1]);
        assert_eq!(group_pubkeys[1], group_pubkeys[2]);
        assert_eq!(group_pubkeys[0].len(), 64);
    }
}
