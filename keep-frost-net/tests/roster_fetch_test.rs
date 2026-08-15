// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Does relay-published roster discovery actually work against a real relay?
//!
//! `fetch_group_roster` had no coverage at all, and kind 21101 sits in the
//! ephemeral range (NIP-01, 20000-29999) just like the round kinds do. Relays
//! forward ephemeral events to live subscribers and never store them, so a REQ
//! issued after the announcement was published returns EOSE with nothing. This
//! test pins down whether the publish-then-fetch flow the CLI's `--publish` path
//! depends on can work.

use std::time::Duration;

use keep_frost_net::dkg::{fetch_group_roster, frost_group_id, DKG_KIND_ANNOUNCE};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;

/// Publish an announcement, then discover it the way the CLI does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_roster_can_be_discovered_from_a_relay() {
    let relay = MockRelay::run().await.expect("mock relay");
    let url = relay.url().await.to_string();

    let k1 = Keys::generate();
    let k2 = Keys::generate();
    let npubs: Vec<String> = [&k1, &k2]
        .iter()
        .map(|k| k.public_key().to_bech32().unwrap())
        .collect();
    let group_id = hex::encode(frost_group_id("discovery", 2, 2, &npubs));

    let coordinator = Client::new(Keys::generate());
    coordinator.add_relay(&url).await.expect("add relay");
    coordinator.connect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut builder = EventBuilder::new(Kind::Custom(DKG_KIND_ANNOUNCE), r#"{"name":"discovery"}"#)
        .tag(Tag::custom(TagKind::custom("d"), [group_id.clone()]))
        .tag(Tag::custom(TagKind::custom("threshold"), ["2".to_string()]))
        .tag(Tag::custom(
            TagKind::custom("participants"),
            ["2".to_string()],
        ));
    for (i, npub) in npubs.iter().enumerate() {
        builder = builder.tag(Tag::custom(
            TagKind::custom("p"),
            [npub.clone(), String::new(), (i + 1).to_string()],
        ));
    }
    let ev = builder.sign_with_keys(&Keys::generate()).expect("sign");
    coordinator.send_event(&ev).await.expect("publish");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let reader = Client::new(Keys::generate());
    reader.add_relay(&url).await.expect("add relay");
    reader.connect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let found = fetch_group_roster(&reader, &group_id).await;

    coordinator.disconnect().await;
    reader.disconnect().await;

    let roster = found.expect(
        "a published roster must be discoverable; if this fails because the relay \
         stored nothing, the announcement kind is ephemeral and discovery cannot work",
    );
    assert_eq!(roster.participants, 2);
    assert_eq!(roster.threshold, 2);
    assert_eq!(*roster.expected_pubkey(1).unwrap(), k1.public_key());
}
