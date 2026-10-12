// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What the gateway keeps for approvals over Nostr: the approver devices and
//! the freeze epoch in the vault, the wraps it opens outside its state lock,
//! the queue of wraps waiting for the relay helper, and the link to it.
//!
//! The approver devices, their freeze counters, the freeze epoch and recent
//! denials live in the vault under [`STORE_KEY`], beside the agent ledgers
//! (see [`crate::approval::Store`]). The channel key never does: it is a
//! credential of its own, sealed to the host, and the vault records only its
//! public key, so a gateway started with another key, or none, is refused
//! while an approver is registered.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use keep_approval::wrap::{self, Candidate, Opened, SeenWraps, TagKey};
use keep_approval::Hex32;
use nostr_sdk::prelude::{Event, Keys};
use tokio::sync::Notify;

pub use crate::approval::{
    OwedEntry, RegisteredDevice, Store, StoredDevice, DENIALS_TO_FREEZE, DENIAL_WINDOW_SECS,
    STORE_KEY,
};

/// The most requests parked at once, across every credential.
pub const MAX_PARKED: usize = 16;

/// Of [`MAX_PARKED`], how many only management changes may take, so agents
/// re-parking cannot lock the owner out of issuing, unfreezing and changing
/// who approves.
pub const MANAGEMENT_RESERVED: usize = 2;

/// How long a pairing session lasts.
pub const PAIRING_SECS: u64 = 600;

/// How often an anchor goes to every approver.
pub const ANCHOR_EVERY_SECS: u64 = 900;

/// Wraps waiting for the relay helper at most.
pub const OUTBOX_CAPACITY: usize = 4_096;

/// Lock `mutex`, taking its value even if a thread panicked holding it: the
/// inbox and the outbox hold nothing a half-done update could make unsafe
/// to use, and approvals must not stop because of it.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where a wrap came from, by the tag it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A registered device, by its transport key.
    Device([u8; 32]),
    /// The open pairing session.
    Pairing,
}

/// What opens the wraps arriving for the channel key, outside the gateway's
/// state lock: the tag keys of every registered device and of the open
/// pairing session, and the wraps already opened.
pub struct Inbox {
    channel: Keys,
    candidates: Vec<Candidate<Source>>,
    seen: SeenWraps,
}

impl Inbox {
    pub(crate) fn new(channel: Keys) -> Self {
        Self {
            channel,
            candidates: Vec::new(),
            seen: SeenWraps::default(),
        }
    }

    /// Expect wraps from `devices`, and from a pairing session with `secret`.
    pub(crate) fn expect(&mut self, devices: &[StoredDevice], secret: Option<&[u8; 32]>) {
        let mut candidates = Vec::with_capacity(devices.len() + 1);
        for d in devices {
            match TagKey::gateway(&self.channel, &d.transport.0) {
                Ok(tag_key) => candidates.push(Candidate::Peer {
                    id: Source::Device(d.transport.0),
                    tag_key,
                    sender: d.transport.0,
                }),
                Err(e) => tracing::error!(error = %e, "an approver device's key is not usable"),
            }
        }
        if let Some(secret) = secret {
            candidates.push(Candidate::Pairing {
                id: Source::Pairing,
                tag_key: TagKey::pairing_gateway(secret),
            });
        }
        self.candidates = candidates;
    }

    /// Open `event` if it carries the tag of an expected sender, by the
    /// receiver's clock `now`; anything else is dropped unopened, and a wrap
    /// already opened is dropped before it is decrypted again.
    pub fn open(&mut self, event: &Event, now: u64) -> Option<Opened<Source>> {
        match wrap::open(&self.channel, event, &self.candidates, &mut self.seen, now) {
            Ok(opened) => Some(opened),
            Err(keep_approval::Error::NotOurs) => None,
            Err(e) => {
                tracing::warn!(error = %e, "a tagged wrap for the channel key did not open");
                None
            }
        }
    }
}

/// What a queued wrap carries, for choosing what to drop when the queue is
/// full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carries {
    /// A request, worthless once its deadline passes (gateway calendar
    /// time).
    Request { expires: u64 },
    /// Anything else: an anchor, an outcome, a pairing answer.
    Other,
}

/// The wraps waiting for the relay helper, oldest first. When full, a new
/// wrap first displaces a request already past its deadline, then the
/// oldest request; an anchor or an outcome is never dropped to make room for
/// a request, and when only such wraps are queued the oldest goes.
#[derive(Default)]
pub struct Outbox {
    queue: Mutex<VecDeque<(Event, Carries)>>,
    ready: Notify,
}

impl Outbox {
    /// Queue `event`, by the gateway's calendar time `now`.
    pub fn push(&self, event: Event, carries: Carries, now: u64) {
        let mut queue = lock(&self.queue);
        if queue.len() >= OUTBOX_CAPACITY {
            queue.retain(|(_, c)| !matches!(c, Carries::Request { expires } if *expires <= now));
        }
        if queue.len() >= OUTBOX_CAPACITY {
            let oldest_request = queue
                .iter()
                .position(|(_, c)| matches!(c, Carries::Request { .. }));
            match (oldest_request, carries) {
                (Some(i), _) => {
                    queue.remove(i);
                }
                (None, Carries::Request { .. }) => {
                    tracing::warn!(
                        "a request to the approvers was dropped: the relay queue is full"
                    );
                    return;
                }
                (None, Carries::Other) => {
                    queue.pop_front();
                }
            }
            tracing::warn!("the relay queue is full: the stalest message was dropped");
        }
        queue.push_back((event, carries));
        drop(queue);
        self.ready.notify_one();
    }

    /// The next wrap, waiting for one.
    pub async fn pop(&self) -> Event {
        loop {
            let notified = self.ready.notified();
            if let Some((event, _)) = lock(&self.queue).pop_front() {
                return event;
            }
            notified.await;
        }
    }

    /// The next wrap, if one is queued.
    pub fn try_pop(&self) -> Option<Event> {
        lock(&self.queue).pop_front().map(|(event, _)| event)
    }

    /// How many wraps are queued.
    pub fn len(&self) -> usize {
        lock(&self.queue).len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What the relay connection needs from the gateway: the wraps to publish,
/// the inbox to open what arrives, and what to tell the helper.
pub struct RelayLink {
    pub outbox: Arc<Outbox>,
    pub inbox: Arc<Mutex<Inbox>>,
    pub relays: Vec<String>,
    /// The channel public key, which the subscription asks for wraps to.
    pub channel: [u8; 32],
}

/// The grant an `issue_credential` change carries: the gateway's grant with
/// every number a decimal string and every list in ascending order, so it
/// has one form. Every field is named, so a field added to the grant fails
/// to compile here until the change carries it.
pub fn change_grant(grant: &crate::policy::Grant) -> keep_approval::change::ChangeGrant {
    use keep_approval::change::{ChangeBitcoin, ChangeGrant, ChangeLimits, Decimal};
    let crate::policy::Grant {
        keys,
        operations,
        event_kinds,
        nip44_peers,
        bitcoin,
        limits,
    } = grant;
    let crate::policy::RequestLimits {
        per_minute,
        per_hour,
        per_day,
    } = limits;
    let mut operations: Vec<String> = operations
        .iter()
        .map(|op: &crate::scope::Operation| op.as_str().to_string())
        .collect();
    operations.sort();
    ChangeGrant {
        keys: keys.iter().copied().map(Hex32).collect(),
        operations,
        event_kinds: event_kinds.iter().map(|&k| Decimal(u64::from(k))).collect(),
        nip44_peers: nip44_peers.iter().copied().map(Hex32).collect(),
        bitcoin: bitcoin.as_ref().map(|b| {
            let crate::policy::BitcoinGrant {
                network,
                per_psbt_sats,
                window_sats,
                approval_above_sats,
                address_allowlist,
            } = b;
            ChangeBitcoin {
                network: network.to_string(),
                per_psbt_sats: Decimal(*per_psbt_sats),
                window_sats: Decimal(*window_sats),
                approval_above_sats: approval_above_sats.map(Decimal),
                address_allowlist: address_allowlist
                    .as_ref()
                    .map(|a| a.iter().cloned().collect()),
            }
        }),
        limits: ChangeLimits {
            per_minute: Decimal(u64::from(*per_minute)),
            per_hour: Decimal(u64::from(*per_hour)),
            per_day: Decimal(u64::from(*per_day)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BitcoinGrant, Grant, RequestLimits, ReservedKeys};
    use crate::scope::Operation;
    use keep_approval::change::{Change, OPERATIONS};
    use keep_approval::Hex16;
    use keep_bitcoin::Network;

    /// Every operation the gateway knows is one an approver accepts.
    #[test]
    fn every_operation_is_one_a_change_may_name() {
        for op in [
            Operation::GetPublicKey,
            Operation::SignNostrEvent,
            Operation::Nip44Encrypt,
            Operation::Nip44Decrypt,
            Operation::GetBitcoinAddress,
            Operation::SignPsbt,
        ] {
            assert!(OPERATIONS.contains(&op.as_str()), "{}", op.as_str());
        }
    }

    /// A validated grant becomes a change grant an approver parses, for
    /// every network, with lists in the order it checks.
    #[test]
    fn a_grant_becomes_a_change_an_approver_accepts() {
        for network in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let address = match network {
                Network::Bitcoin => "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                Network::Regtest => "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                _ => "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            };
            let grant = Grant {
                keys: [[2; 32], [1; 32]].into(),
                operations: [
                    Operation::SignPsbt,
                    Operation::GetPublicKey,
                    Operation::SignNostrEvent,
                    Operation::GetBitcoinAddress,
                ]
                .into(),
                event_kinds: [30_000, 1, 7].into(),
                nip44_peers: Default::default(),
                bitcoin: Some(BitcoinGrant {
                    network,
                    per_psbt_sats: 1_000,
                    window_sats: 5_000,
                    approval_above_sats: Some(2_000),
                    address_allowlist: Some([address.to_string()].into()),
                }),
                limits: RequestLimits::default(),
            }
            .validated(&ReservedKeys::new())
            .unwrap();
            let change = Change::IssueCredential {
                id: Hex16([1; 16]),
                name: "agent".into(),
                uid: keep_approval::change::Decimal(1001),
                created_at: keep_approval::change::Decimal(1),
                expires_at: keep_approval::change::Decimal(2),
                grant: change_grant(&grant),
            };
            let parsed = Change::parse(
                &keep_approval::change::parse_without_duplicates(
                    &serde_json::to_string(&change.to_value()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap_or_else(|e| panic!("{network}: {e}"));
            assert_eq!(parsed, change);
        }
    }

    #[test]
    fn three_denials_in_a_day_freeze_and_start_afresh() {
        let mut store = Store::default();
        let id = [5; 16];
        assert!(!store.note_denial(id, 0));
        assert!(!store.note_denial(id, 10));
        // The first one has left the window.
        assert!(!store.note_denial(id, DENIAL_WINDOW_SECS));
        assert!(store.note_denial(id, DENIAL_WINDOW_SECS + 1));
        assert!(store.denials.is_empty());
        assert!(!store.note_denial(id, DENIAL_WINDOW_SECS + 2));
        // Another credential's denials are its own, and old lists are pruned.
        assert!(!store.note_denial([6; 16], 5 * DENIAL_WINDOW_SECS));
        assert_eq!(store.denials.len(), 1);
    }
}
