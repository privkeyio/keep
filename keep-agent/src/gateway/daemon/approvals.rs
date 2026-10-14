// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What the gateway keeps for approvals over Nostr: the wraps it opens
//! outside its state lock, the queue of wraps waiting for the relay helper,
//! and the link to it.
//!
//! The approver devices and the rest of the approval state live in the
//! vault beside the agent ledgers (see [`crate::approval::Store`]), and the
//! freeze epoch in the vault's own config. The channel key never does: it is a
//! credential of its own, sealed to the host, and the vault records only its
//! public key, so a gateway started with another key, or none, is refused
//! while an approver is registered.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use keep_approval::wrap::{self, Candidate, Opened, SeenWraps, TagKey};
use keep_approval::Hex32;
use nostr_sdk::prelude::{Event, Keys};
use tokio::sync::Notify;

pub use crate::approval::{Store, StoredDevice};

/// The most requests parked at once, across every credential.
pub const MAX_PARKED: usize = 16;

/// Of [`MAX_PARKED`], how many only management changes may take, so agents
/// re-parking cannot lock the owner out of issuing, unfreezing and changing
/// who approves.
pub const MANAGEMENT_RESERVED: usize = 2;

/// Freezes one device may send in a minute; more are dropped unanswered.
/// A phone resends a freeze no anchor has shown every 15 seconds and its
/// owner may freeze a few credentials at once, so this is well above use,
/// while it bounds the anchors and the work a stolen transport key, which
/// needs no biometric, can cause.
pub const FREEZES_PER_MINUTE: u32 = 30;

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
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        lock(&self.queue).len()
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
/// to compile here until the change carries it. Each secret carries its name
/// and kind from `info`, so the approver can tell which secret it is.
pub fn change_grant(
    grant: &crate::policy::Grant,
    info: impl Fn(&[u8; 32]) -> keep_core::error::Result<keep_core::secret::SecretInfo>,
) -> crate::error::Result<keep_approval::change::ChangeGrant> {
    use keep_approval::change::{
        ChangeBitcoin, ChangeGrant, ChangeLimits, ChangeRule, ChangeSecret, Decimal,
    };
    let crate::policy::Grant {
        keys,
        operations,
        event_kinds,
        nip44_peers,
        bitcoin,
        limits,
        secrets,
    } = grant;
    let crate::policy::RequestLimits {
        per_minute,
        per_hour,
        per_day,
    } = limits;
    let secrets = secrets
        .iter()
        .map(|entry| {
            let crate::inject::rule::SecretGrant { secret, http, ssh } = entry;
            let unusable = |why: &str| {
                crate::error::AgentError::ScopeViolation(format!(
                    "secret {} {why}",
                    hex::encode(secret)
                ))
            };
            let info = info(secret).map_err(|_| unusable("is not in the vault"))?;
            keep_approval::change::check_label(&info.name, "secret name")
                .map_err(|_| unusable("has a name an approver cannot be shown; rename it"))?;
            let http = http
                .iter()
                .map(|rule| {
                    let crate::inject::rule::HttpRule {
                        host,
                        port,
                        methods,
                        path_prefix,
                        header,
                        format,
                        agent_headers,
                    } = rule;
                    ChangeRule {
                        host: host.clone(),
                        port: Decimal(u64::from(*port)),
                        path_prefix: path_prefix.clone(),
                        methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
                        header: header.clone(),
                        format: format.clone(),
                        agent_headers: agent_headers.clone(),
                    }
                })
                .collect();
            Ok(ChangeSecret {
                secret: Hex32(*secret),
                name: info.name,
                kind: info.kind.as_str().to_string(),
                http,
                ssh: ssh.as_ref().map(crate::ssh::SshRule::change),
            })
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    let mut operations: Vec<String> = operations
        .iter()
        .map(|op: &crate::scope::Operation| op.as_str().to_string())
        .collect();
    operations.sort();
    Ok(ChangeGrant {
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
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::DENIAL_WINDOW_SECS;
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
            Operation::HttpRequest,
            Operation::SshSign,
        ] {
            assert!(OPERATIONS.contains(&op.as_str()), "{}", op.as_str());
        }
    }

    fn no_secret(_: &[u8; 32]) -> keep_core::error::Result<keep_core::secret::SecretInfo> {
        Err(keep_core::error::KeepError::NotFound("no secret".into()))
    }

    /// A grant with secrets becomes a change an approver parses: rules and
    /// methods in the order it checks, each secret named and of its kind. A
    /// secret the vault lacks, or one named in a way an approver cannot show,
    /// makes no change.
    #[test]
    fn a_grant_with_secrets_becomes_a_change_an_approver_accepts() {
        use crate::inject::rule::{HttpRule, Method, SecretGrant};
        use keep_core::secret::{SecretInfo, SecretKind};
        let rule = |host: &str, prefix: &str, methods: Vec<Method>| HttpRule {
            host: host.into(),
            port: 443,
            methods,
            path_prefix: prefix.into(),
            header: "authorization".into(),
            format: "Bearer {}".into(),
            agent_headers: vec!["idempotency-key".into()],
        };
        let grant = Grant {
            keys: Default::default(),
            operations: [Operation::HttpRequest].into(),
            event_kinds: Default::default(),
            nip44_peers: Default::default(),
            bitcoin: None,
            limits: RequestLimits::default(),
            secrets: vec![
                SecretGrant {
                    secret: [1; 32],
                    http: vec![
                        rule(
                            "api.example.com",
                            "/v1/a",
                            vec![Method::Patch, Method::Post],
                        ),
                        rule("api.example.com", "/v1/b", vec![Method::Get]),
                    ],
                    ssh: None,
                },
                SecretGrant {
                    secret: [2; 32],
                    http: vec![rule("xn--bcher-kva.example", "/x", vec![Method::Delete])],
                    ssh: None,
                },
            ],
        }
        .validated(&ReservedKeys::new())
        .unwrap();
        let info = |id: &[u8; 32]| {
            Ok(SecretInfo {
                name: format!("token {} \u{1f511}", id[0]),
                kind: SecretKind::ApiToken,
                sealed: false,
            })
        };
        let shown = change_grant(&grant, info).unwrap();
        assert_eq!(shown.secrets.len(), 2);
        assert_eq!(shown.secrets[0].http[0].methods, ["PATCH", "POST"]);
        assert_eq!(shown.secrets[0].kind, "api_token");
        let change = Change::IssueCredential {
            id: Hex16([1; 16]),
            name: "agent".into(),
            uid: keep_approval::change::Decimal(1001),
            created_at: keep_approval::change::Decimal(1),
            expires_at: keep_approval::change::Decimal(2),
            grant: shown,
        };
        let parsed = Change::parse(
            &keep_approval::change::parse_without_duplicates(
                &serde_json::to_string(&change.to_value()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, change);

        assert!(change_grant(&grant, no_secret).is_err());
        let hidden = |_: &[u8; 32]| {
            Ok(SecretInfo {
                name: "api\u{202e}kcah".into(),
                kind: SecretKind::ApiToken,
                sealed: false,
            })
        };
        assert!(change_grant(&grant, hidden).is_err());
    }

    /// An SSH key's rule becomes a change an approver parses, its host keys
    /// shown by type and fingerprint.
    #[test]
    fn an_ssh_grant_becomes_a_change_an_approver_accepts() {
        use crate::inject::rule::SecretGrant;
        use crate::ssh::wire::put_string;
        use keep_core::secret::{SecretInfo, SecretKind};
        let host = |seed: u8| {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let mut blob = Vec::new();
            put_string(&mut blob, b"ssh-ed25519");
            put_string(&mut blob, key.verifying_key().as_bytes());
            blob
        };
        let (a, b) = (host(1), host(2));
        let mut host_keys = vec![
            crate::ssh::public_key_text(&a).unwrap(),
            crate::ssh::public_key_text(&b).unwrap(),
        ];
        host_keys.sort();
        let grant = Grant {
            keys: Default::default(),
            operations: [Operation::SshSign].into(),
            event_kinds: Default::default(),
            nip44_peers: Default::default(),
            bitcoin: None,
            limits: RequestLimits::default(),
            secrets: vec![SecretGrant {
                secret: [3; 32],
                http: vec![],
                ssh: Some(crate::ssh::SshRule {
                    users: vec!["git".into()],
                    host_keys,
                    sshsig_namespaces: vec!["git".into()],
                }),
            }],
        }
        .validated(&ReservedKeys::new())
        .unwrap();
        let info = |_: &[u8; 32]| {
            Ok(SecretInfo {
                name: "deploy key".into(),
                kind: SecretKind::SshKey,
                sealed: false,
            })
        };
        let shown = change_grant(&grant, info).unwrap();
        let ssh = shown.secrets[0].ssh.as_ref().unwrap();
        let mut want = vec![
            crate::ssh::host_key_label(&a).unwrap(),
            crate::ssh::host_key_label(&b).unwrap(),
        ];
        want.sort();
        assert_eq!(ssh.host_keys, want);
        assert_eq!(shown.secrets[0].kind, "ssh_key");
        let change = Change::IssueCredential {
            id: Hex16([1; 16]),
            name: "agent".into(),
            uid: keep_approval::change::Decimal(1001),
            created_at: keep_approval::change::Decimal(1),
            expires_at: keep_approval::change::Decimal(2),
            grant: shown,
        };
        let parsed = Change::parse(
            &keep_approval::change::parse_without_duplicates(
                &serde_json::to_string(&change.to_value()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, change);
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
                secrets: Vec::new(),
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
                grant: change_grant(&grant, no_secret).unwrap(),
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

    /// A full outbox makes room by dropping requests past their deadline,
    /// then the oldest request; a request never displaces anything else, and
    /// when nothing else is queued the oldest message goes.
    #[test]
    fn a_full_outbox_drops_stale_requests_first_and_never_an_anchor_for_one() {
        use nostr_sdk::prelude::EventBuilder;
        let keys = Keys::generate();
        let event = |text: &str| EventBuilder::text_note(text).sign_with_keys(&keys).unwrap();
        let now = 1_000;
        let live = Carries::Request { expires: now + 100 };
        let filler = event("filler");
        // A full outbox that starts with `first`, then `push`ed, drained.
        let after = |first: &[(&str, Carries)], push: (&str, Carries)| {
            let outbox = Outbox::default();
            for (text, carries) in first {
                outbox.push(event(text), *carries, now);
            }
            while outbox.len() < OUTBOX_CAPACITY {
                outbox.push(filler.clone(), Carries::Other, now);
            }
            outbox.push(event(push.0), push.1, now);
            let mut kept = Vec::new();
            while let Some(e) = outbox.try_pop() {
                kept.push(e.content);
            }
            assert_eq!(kept.len(), OUTBOX_CAPACITY);
            kept
        };
        // A request past its deadline goes first, though an older one waits.
        let kept = after(
            &[
                ("anchor", Carries::Other),
                ("old request", live),
                ("expired request", Carries::Request { expires: now }),
            ],
            ("new request", live),
        );
        assert_eq!(kept[..2], ["anchor", "old request"]);
        assert_eq!(kept.last().unwrap(), "new request");
        // Then the oldest request, never the anchor before it.
        let kept = after(
            &[
                ("anchor", Carries::Other),
                ("old request", live),
                ("live request", live),
            ],
            ("outcome", Carries::Other),
        );
        assert_eq!(kept[..2], ["anchor", "live request"]);
        assert_eq!(kept.last().unwrap(), "outcome");
        // A request does not displace an anchor or an outcome.
        let kept = after(&[("anchor", Carries::Other)], ("request", live));
        assert_eq!(kept[0], "anchor");
        assert!(!kept.iter().any(|k| k == "request"));
        // Anything else displaces the oldest message.
        let kept = after(&[("anchor", Carries::Other)], ("outcome", Carries::Other));
        assert_ne!(kept[0], "anchor");
        assert_eq!(kept.last().unwrap(), "outcome");
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
