// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What the gateway keeps for approvals over Nostr: the approver devices and
//! the freeze epoch in the vault, the wraps it opens outside its state lock,
//! and the link to the relay helper.
//!
//! The approver devices, their freeze counters, the freeze epoch and recent
//! denials live in the vault under [`STORE_KEY`], beside the agent ledgers.
//! The channel key never does: it is a credential of its own, sealed to the
//! host, and the vault records only its public key, so a gateway started
//! with another key, or none, is refused while an approver is registered.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use keep_approval::sig::Device;
use keep_approval::wrap::{self, Candidate, Opened, SeenWraps, TagKey};
use keep_approval::{Hex16, Hex32};
use keep_core::Keep;
use nostr_sdk::prelude::{Event, Keys};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::error::{AgentError, Result};
use crate::policy::ReservedKeys;
use crate::scope::Operation;

/// The ledger key the approval state is stored under: neither a credential's
/// id (16 bytes) nor a wallet's.
pub const STORE_KEY: &[u8] = b"approvals";

/// The most requests parked at once, across every credential.
pub const MAX_PARKED: usize = 16;

/// How long a pairing session lasts.
pub const PAIRING_SECS: u64 = 600;

/// How often an anchor goes to every approver.
pub const ANCHOR_EVERY_SECS: u64 = 900;

/// Denials of one credential's requests within [`DENIAL_WINDOW_SECS`] that
/// freeze it.
pub const DENIALS_TO_FREEZE: usize = 3;

/// The window denials are counted in.
pub const DENIAL_WINDOW_SECS: u64 = 24 * 60 * 60;

/// Wraps waiting for the relay helper at most; past it the oldest are
/// dropped, which a relay could do anyway.
pub const OUTBOX_CAPACITY: usize = 4_096;

/// A registered approver device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDevice {
    pub transport: Hex32,
    pub approver: Hex32,
    pub label: String,
    /// The last freeze or unfreeze counter accepted from the device.
    pub counter: u64,
}

impl StoredDevice {
    pub fn device(&self) -> Device {
        Device {
            transport: self.transport.0,
            approver: self.approver.0,
        }
    }

    pub fn fingerprint(&self) -> String {
        keep_approval::sig::fingerprint(&self.transport.0, &self.approver.0)
    }
}

/// The approval state the vault holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    /// The channel public key, recorded when the first approver is
    /// registered and cleared with the last.
    pub channel: Option<Hex32>,
    pub devices: Vec<StoredDevice>,
    /// One more on every freeze and unfreeze, from any source.
    pub epoch: u64,
    /// When each credential's requests were last denied, on the budget clock,
    /// within the denial window.
    pub denials: BTreeMap<Hex16, Vec<u64>>,
}

impl Store {
    /// The store in the vault; empty when there is none.
    pub fn load(keep: &Keep) -> Result<Self> {
        match keep.load_agent_ledger(STORE_KEY)? {
            None => Ok(Self::default()),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                AgentError::Other(format!(
                    "the approval state in the vault does not decode: {e}"
                ))
            }),
        }
    }

    /// Write the store to the vault, durably.
    pub fn save(&self, keep: &mut Keep) -> Result<()> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| AgentError::Serialization(e.to_string()))?;
        keep.update_agent_ledgers(&[STORE_KEY], |_| Ok(vec![bytes]))?;
        Ok(())
    }

    /// The device whose transport key is `transport`.
    pub fn device(&self, transport: &[u8; 32]) -> Option<&StoredDevice> {
        self.devices.iter().find(|d| d.transport.0 == *transport)
    }

    /// Every device key, and the channel key when one is given: the keys no
    /// grant may name.
    pub fn reserved(&self, channel: Option<[u8; 32]>) -> ReservedKeys {
        self.devices
            .iter()
            .flat_map(|d| [d.transport.0, d.approver.0])
            .chain(channel)
            .collect()
    }

    /// Note a denial of credential `id` at `now`, and say whether it makes
    /// [`DENIALS_TO_FREEZE`] within the window, which then starts afresh.
    pub fn note_denial(&mut self, id: [u8; 16], now: u64) -> bool {
        let list = self.denials.entry(Hex16(id)).or_default();
        list.retain(|&at| now.saturating_sub(at) < DENIAL_WINDOW_SECS);
        list.push(now);
        let freeze = list.len() >= DENIALS_TO_FREEZE;
        if freeze {
            self.denials.remove(&Hex16(id));
        }
        self.denials.retain(|_, l| {
            l.iter()
                .any(|&at| now.saturating_sub(at) < DENIAL_WINDOW_SECS)
        });
        freeze
    }
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
            match TagKey::for_peer(&self.channel, &d.transport.0) {
                Ok(tag_key) => candidates.push(Candidate {
                    id: Source::Device(d.transport.0),
                    tag_key,
                    sender: Some(d.transport.0),
                }),
                Err(e) => tracing::error!(error = %e, "an approver device's key is not usable"),
            }
        }
        if let Some(secret) = secret {
            candidates.push(Candidate {
                id: Source::Pairing,
                tag_key: TagKey::for_pairing(secret),
                sender: None,
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

/// What the relay connection needs from the gateway: the wraps to publish,
/// the inbox to open what arrives, and what to tell the helper.
pub struct RelayLink {
    pub outbox: mpsc::Receiver<Event>,
    pub inbox: Arc<Mutex<Inbox>>,
    pub relays: Vec<String>,
    /// The channel public key, which the subscription asks for wraps to.
    pub channel: [u8; 32],
}

/// The grant an `issue_credential` change carries: the gateway's grant with
/// every number a decimal string and every list in ascending order, so it
/// has one form.
pub fn change_grant(grant: &crate::policy::Grant) -> keep_approval::change::ChangeGrant {
    use keep_approval::change::{ChangeBitcoin, ChangeGrant, ChangeLimits, Decimal};
    let mut operations: Vec<String> = grant
        .operations
        .iter()
        .map(|op: &Operation| op.as_str().to_string())
        .collect();
    operations.sort();
    ChangeGrant {
        keys: grant.keys.iter().copied().map(Hex32).collect(),
        operations,
        event_kinds: grant
            .event_kinds
            .iter()
            .map(|&k| Decimal(u64::from(k)))
            .collect(),
        nip44_peers: grant.nip44_peers.iter().copied().map(Hex32).collect(),
        bitcoin: grant.bitcoin.as_ref().map(|b| ChangeBitcoin {
            network: b.network.to_string(),
            per_psbt_sats: Decimal(b.per_psbt_sats),
            window_sats: Decimal(b.window_sats),
            approval_above_sats: b.approval_above_sats.map(Decimal),
            address_allowlist: b
                .address_allowlist
                .as_ref()
                .map(|a| a.iter().cloned().collect()),
        }),
        limits: ChangeLimits {
            per_minute: Decimal(u64::from(grant.limits.per_minute)),
            per_hour: Decimal(u64::from(grant.limits.per_hour)),
            per_day: Decimal(u64::from(grant.limits.per_day)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BitcoinGrant, Grant, RequestLimits};
    use keep_approval::change::{Change, OPERATIONS};
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
            let parsed = Change::parse_text(&serde_json::to_string(&change.to_value()).unwrap())
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
