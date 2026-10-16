// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Helpers shared by the keep-frost-net test binaries. Each binary includes
//! this with `mod common;`, so not every binary uses every item.
#![allow(dead_code)]

/// Start a `MockRelay`, retrying a start that lost the race for its port.
///
/// `nostr-relay-builder` picks a random free port by binding a probe listener
/// and dropping it before binding the address for real, so two starts racing in
/// this binary's parallel tests can pick the same port and the loser gets
/// `AddrInUse`. Each attempt is a fresh `MockRelay`, which is what draws a new
/// port: the chosen port is memoized per relay. Binding port 0 instead is not
/// an option, because the relay reports the address it was given, so its URL
/// would say port 0.
pub async fn start_mock_relay() -> nostr_relay_builder::MockRelay {
    let mut last = None;
    for _ in 0..8 {
        match nostr_relay_builder::MockRelay::run().await {
            Ok(relay) => return relay,
            Err(e) => last = Some(e),
        }
    }
    panic!("mock relay start: {}", last.expect("a failure to report"));
}
