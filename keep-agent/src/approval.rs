// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Requests parked for an approver, and the approval that clears one.
//!
//! A request sent to the approvers is parked as a [`Parked`]: the exact
//! object to sign or apply, and the request built from that object, with its
//! hash, so what the approver is shown and what is carried out cannot
//! differ. An [`Approval`] is made only by [`Approval::verify`], which checks
//! the approver's signed decision over that request's id and hash, and it
//! carries the parked request, so [`crate::policy::evaluate_approved`]
//! evaluates exactly what was approved, and only once.
//!
//! The approver devices live in the vault as a [`Store`]. Only the store
//! issues a [`RegisteredDevice`], and [`Approval::verify`] takes one, so an
//! approval's type proves that a device registered in the vault approved
//! the request.

use keep_approval::binding::{
    Network as WireNetwork, NostrPayload, Payload, RequestDraft, UnsignedEventFields,
};
use keep_approval::change::Change;
use keep_approval::messages::{
    AnchorState, Budget, CredentialRef, Decision as SignedDecision, Reason, Request as WireRequest,
    Verdict,
};
use keep_approval::messages::{LogPoint, Unfrozen, MAX_UNFROZEN};
use keep_approval::psbt::PsbtPayload;
use keep_approval::sig::{self, Alg, Device};
use keep_approval::{Hex16, Hex32, Hex33, Hex64};
use keep_bitcoin::bitcoin::Psbt;
use keep_bitcoin::PsbtAnalysis;
use keep_core::audit::AuditEventType;
use keep_core::Keep;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{AgentError, Result};
use crate::policy::{Request, ReservedKeys};

/// The ledger key the approval state is stored under: neither a credential's
/// id (16 bytes) nor a wallet's.
pub const STORE_KEY: &[u8] = b"approvals";

/// Denials of one credential's requests within [`DENIAL_WINDOW_SECS`] that
/// freeze it.
pub const DENIALS_TO_FREEZE: usize = 3;

/// The window denials are counted in.
pub const DENIAL_WINDOW_SECS: u64 = 24 * 60 * 60;

/// A registered approver device, as the vault holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDevice {
    pub transport: Hex32,
    /// The approver key's type, from the device's `pair`.
    pub alg: Alg,
    pub approver: Hex33,
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
        sig::fingerprint(&self.transport.0, &self.approver.0)
    }
}

/// A device the store holds as registered, as only [`Store::registered`]
/// gives one out: what [`Approval::verify`] checks a decision against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredDevice {
    device: Device,
}

impl RegisteredDevice {
    pub fn device(&self) -> &Device {
        &self.device
    }
}

/// Owner entries kept owed at most; past it, more of a type already owed
/// are only counted.
pub const MAX_OWED: usize = 64;

/// An owner entry that could not be written yet, kept with the store so a
/// restart does not lose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwedEntry {
    pub event: AuditEventType,
    pub reason: String,
    /// Entries of the same type owed once [`MAX_OWED`] was reached, whose
    /// text was not kept.
    #[serde(default)]
    pub more: u64,
}

impl OwedEntry {
    /// The entry's text as written, saying how many more were not kept.
    pub fn text(&self) -> String {
        match self.more {
            0 => self.reason.clone(),
            more => format!(
                "{} (and {more} more {} entries whose text was not kept while the log could \
                 not be written)",
                self.reason, self.event
            ),
        }
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
    /// When each credential's requests were last denied, on the budget clock,
    /// within the denial window.
    pub denials: BTreeMap<Hex16, Vec<u64>>,
    /// The audit log's place in the last anchor sent, to any device in any
    /// message: the next anchor's `prev`.
    pub last_anchor: Option<LogPoint>,
    /// The unfreezes applied lately, with the gateway calendar time of each,
    /// newest last: what anchors list so every phone can explain a freeze
    /// cleared.
    pub unfrozen: Vec<(Unfrozen, u64)>,
    /// Owner entries not written yet.
    pub owed: Vec<OwedEntry>,
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

    /// The store as the bytes the vault keeps.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AgentError::Serialization(e.to_string()))
    }

    /// Write the store to the vault, durably.
    pub fn save(&self, keep: &mut Keep) -> Result<()> {
        let bytes = self.encode()?;
        keep.update_agent_ledgers(&[STORE_KEY], |_| Ok(vec![bytes]))?;
        Ok(())
    }

    /// Owe owner entry `reason` of type `event`. Past [`MAX_OWED`], one of
    /// a type already owed is counted on the newest of that type, so a flood
    /// cannot grow the store without bound.
    pub fn owe(&mut self, event: AuditEventType, reason: String) {
        if self.owed.len() >= MAX_OWED {
            if let Some(last) = self.owed.iter_mut().rev().find(|o| o.event == event) {
                last.more = last.more.saturating_add(1);
                return;
            }
        }
        self.owed.push(OwedEntry {
            event,
            reason,
            more: 0,
        });
    }

    /// Write the owed entries to `keep`'s log, oldest first, stopping at the
    /// first that still fails, and drop those written. Returns how many.
    pub fn write_owed(&mut self, keep: &mut Keep) -> usize {
        let written = self
            .owed
            .iter()
            .take_while(|o| keep.record_owner_event(o.event, &o.text()).is_ok())
            .count();
        self.owed.drain(..written);
        written
    }

    /// The device whose transport key is `transport`.
    pub fn device(&self, transport: &[u8; 32]) -> Option<&StoredDevice> {
        self.devices.iter().find(|d| d.transport.0 == *transport)
    }

    /// The device whose transport key is `transport`, as the registered
    /// device a decision from it is verified against.
    pub fn registered(&self, transport: &[u8; 32]) -> Option<RegisteredDevice> {
        self.device(transport)
            .map(|d| RegisteredDevice { device: d.device() })
    }

    /// The keys no grant may name: every device's transport key, and the
    /// channel key when one is given. Approver keys are P-256, which no
    /// grant can name.
    pub fn reserved(&self, channel: Option<[u8; 32]>) -> ReservedKeys {
        self.devices
            .iter()
            .map(|d| d.transport.0)
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

    /// Note an unfreeze of `scope` that moved the epoch to `epoch` at
    /// gateway time `at`, keeping those inside the wrap time window, at most
    /// [`MAX_UNFROZEN`].
    pub fn note_unfrozen(&mut self, scope: keep_approval::change::Scope, epoch: u64, at: u64) {
        self.unfrozen.push((Unfrozen { scope, epoch }, at));
        self.prune_unfrozen(at);
    }

    fn prune_unfrozen(&mut self, now: u64) {
        self.unfrozen
            .retain(|(_, at)| now.saturating_sub(*at) <= keep_approval::wrap::WINDOW_PAST_SECS);
        let excess = self.unfrozen.len().saturating_sub(MAX_UNFROZEN);
        self.unfrozen.drain(..excess);
    }

    /// The unfreezes an anchor taken at gateway time `now` lists.
    pub fn recent_unfreezes(&self, now: u64) -> Vec<Unfrozen> {
        let recent: Vec<Unfrozen> = self
            .unfrozen
            .iter()
            .filter(|(_, at)| now.saturating_sub(*at) <= keep_approval::wrap::WINDOW_PAST_SECS)
            .map(|(u, _)| *u)
            .collect();
        let excess = recent.len().saturating_sub(MAX_UNFROZEN);
        recent[excess..].to_vec()
    }
}

/// What a parked request signs or applies once approved, exactly.
pub enum ParkedObject {
    /// The unsigned event signed as it is.
    NostrEvent(UnsignedEventFields),
    /// The PSBT signed unchanged with `key`'s wallet, with the analysis the
    /// policy decided on and the change outputs it verified, each with the
    /// last step of its derivation path.
    Psbt {
        psbt: Box<Psbt>,
        analysis: PsbtAnalysis,
        key: [u8; 32],
        change: Vec<(usize, u32)>,
    },
    /// A management change, applied as it is.
    Management(Change),
}

impl std::fmt::Debug for ParkedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NostrEvent(e) => write!(f, "NostrEvent(kind {})", e.kind),
            Self::Psbt { psbt, .. } => {
                write!(f, "Psbt({})", psbt.unsigned_tx.compute_txid())
            }
            Self::Management(c) => write!(f, "Management(type {})", c.type_code()),
        }
    }
}

/// Everything a request carries besides its object: who asks, when, and
/// the context the approver is shown.
#[derive(Debug, Clone)]
pub struct ParkRequest {
    pub request_id: [u8; 32],
    pub created_at: u64,
    pub deadline_secs: u64,
    pub credential: Option<CredentialRef>,
    pub reason: Reason,
    pub budget: Option<Budget>,
    pub anchor: AnchorState,
}

/// A request waiting for an approver: the object, and the request built
/// from it with its hash.
#[derive(Debug)]
pub struct Parked {
    object: Box<ParkedObject>,
    request: Box<WireRequest>,
    hash: [u8; 32],
}

impl Parked {
    /// Build the request for `object` as the gateway `channel` sends it, with
    /// every check an approver runs and the size limit, and its hash.
    // Only the gateway daemon, which runs on Linux alone, builds one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn new(object: ParkedObject, info: ParkRequest, channel: &[u8; 32]) -> Result<Self> {
        let refuse = |e: keep_approval::Error| match e {
            keep_approval::Error::TooLarge(_) => {
                AgentError::PolicyDenied("the request is too large to approve".into())
            }
            e => AgentError::Other(format!("the approval request cannot be built: {e}")),
        };
        let (payload, key, network) = match &object {
            ParkedObject::NostrEvent(event) => (
                Payload::Nostr(NostrPayload {
                    event: event.clone(),
                }),
                Some(event.pubkey.0),
                None,
            ),
            ParkedObject::Psbt {
                psbt,
                analysis,
                key,
                change,
            } => {
                let network = WireNetwork::from_bitcoin(analysis.network);
                let payload =
                    PsbtPayload::from_psbt(psbt, &analysis.signable_inputs, change, network)
                        .map_err(refuse)?;
                (Payload::Psbt(payload), Some(*key), Some(network))
            }
            ParkedObject::Management(change) => (Payload::Management(change.clone()), None, None),
        };
        let draft = RequestDraft {
            request_id: info.request_id,
            created_at: info.created_at,
            deadline_secs: info.deadline_secs,
            credential: info.credential,
            key,
            network,
            reason: info.reason,
            payload,
            budget: info.budget,
            anchor: info.anchor,
        };
        let (request, hash) = draft.finish(channel).map_err(refuse)?;
        Ok(Self {
            object: Box::new(object),
            request: Box::new(request),
            hash,
        })
    }

    /// The request as approvers are sent it.
    pub fn request(&self) -> &WireRequest {
        &self.request
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request.request_id.0
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The credential the request is about, if any.
    pub fn credential(&self) -> Option<[u8; 16]> {
        self.request.credential.as_ref().map(|c| c.id.0)
    }

    /// When the request was made, on the gateway's calendar clock.
    pub fn created_at(&self) -> u64 {
        self.request.created_at
    }

    pub fn object(&self) -> &ParkedObject {
        &self.object
    }

    /// The key and the policy request an approved agent request is evaluated
    /// as; `None` for a management change.
    pub(crate) fn policy_request(&self) -> Option<([u8; 32], Request<'_>)> {
        match self.object.as_ref() {
            ParkedObject::NostrEvent(event) => {
                Some((event.pubkey.0, Request::SignNostrEvent { kind: event.kind }))
            }
            ParkedObject::Psbt { analysis, key, .. } => {
                Some((*key, Request::SignPsbt { analysis }))
            }
            ParkedObject::Management(_) => None,
        }
    }
}

/// An approver's approval of one parked request. Only [`Approval::verify`]
/// makes one, from a decision that verifies; it is consumed by
/// [`crate::policy::evaluate_approved`] or, for a management change, by
/// [`Approval::into_management`].
#[derive(Debug)]
pub struct Approval {
    approved: Box<Approved>,
}

/// An approved request, handed back once its approval is used: what to sign
/// or apply, and who approved it with which signature.
#[derive(Debug)]
pub struct Approved {
    parked: Parked,
    device: Device,
    sig: Hex64,
}

impl Approval {
    /// Make the approval of `parked` from `decision`, sealed by the
    /// registered `device`'s transport key: it must name the parked
    /// request's id and hash, say approve, and carry a signature by the
    /// device's approver key over the gateway's `channel` key, the approver
    /// key, that hash and the verdict. Anything else hands the parked request
    /// back with the reason.
    // Only the gateway daemon, which runs on Linux alone, builds one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn verify(
        decision: &SignedDecision,
        channel: &[u8; 32],
        device: &RegisteredDevice,
        parked: Parked,
    ) -> std::result::Result<Self, (Parked, String)> {
        match sig::check_decision(
            decision,
            channel,
            &device.device,
            &parked.request_id(),
            &parked.hash,
        ) {
            Ok(Verdict::Approve) => Ok(Self {
                approved: Box::new(Approved {
                    parked,
                    device: device.device,
                    sig: decision.sig,
                }),
            }),
            Ok(Verdict::Deny) => Err((parked, "the decision denies the request".into())),
            Err(e) => Err((parked, e.to_string())),
        }
    }

    pub(crate) fn into_approved(self) -> Approved {
        *self.approved
    }

    /// The approved management change, to apply as it is; an agent request
    /// is handed back, to go through [`crate::policy::evaluate_approved`].
    pub fn into_management(self) -> std::result::Result<(Approved, Change), Self> {
        match self.approved.parked.object.as_ref() {
            ParkedObject::Management(change) => {
                let change = change.clone();
                Ok((*self.approved, change))
            }
            _ => Err(self),
        }
    }
}

impl std::ops::Deref for Approval {
    type Target = Approved;

    fn deref(&self) -> &Approved {
        &self.approved
    }
}

impl Approved {
    pub fn parked(&self) -> &Parked {
        &self.parked
    }

    /// The device whose approver key signed the approval.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// The decision's signature, kept in the audit log as the proof.
    pub fn signature(&self) -> &Hex64 {
        &self.sig
    }

    #[cfg(test)]
    pub fn into_parked(self) -> Parked {
        self.parked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        evaluate_approved, Budgets, Decision, DenyReason, Grant, Ledger, RequestLimits,
    };
    use crate::scope::Operation;
    use keep_approval::messages::V1;
    use keep_approval::sig::ApproverSigningKey;
    use nostr_sdk::prelude::Keys;

    struct Fixture {
        channel: [u8; 32],
        transport: Keys,
        approver: ApproverSigningKey,
        device: RegisteredDevice,
        key: [u8; 32],
    }

    fn fixture() -> Fixture {
        let transport = Keys::generate();
        let approver = ApproverSigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let mut store = Store::default();
        store.devices.push(StoredDevice {
            transport: Hex32(transport.public_key().to_bytes()),
            alg: Alg::P256,
            approver: Hex33(sig::approver_key(&approver)),
            label: "phone".into(),
            counter: 0,
        });
        let device = store
            .registered(&transport.public_key().to_bytes())
            .unwrap();
        Fixture {
            channel: Keys::generate().public_key().to_bytes(),
            transport,
            approver,
            device,
            key: Keys::generate().public_key().to_bytes(),
        }
    }

    fn info(id: u8) -> ParkRequest {
        ParkRequest {
            request_id: [id; 32],
            created_at: 1_791_580_000,
            deadline_secs: 120,
            credential: Some(CredentialRef {
                id: keep_approval::Hex16([7; 16]),
                name: "writer".into(),
                uid: 1001,
            }),
            reason: Reason::Kind { kind: 0 },
            budget: None,
            anchor: AnchorState {
                seq: 1,
                head: Hex32([0; 32]),
                prev: None,
                wallets: vec![],
            },
        }
    }

    fn event(f: &Fixture, content: &str) -> ParkedObject {
        ParkedObject::NostrEvent(UnsignedEventFields {
            pubkey: Hex32(f.key),
            created_at: 1_791_580_000,
            kind: 0,
            tags: vec![],
            content: content.into(),
        })
    }

    fn decision(
        f: &Fixture,
        signer: &ApproverSigningKey,
        parked: &Parked,
        verdict: Verdict,
    ) -> SignedDecision {
        sig::decision(
            signer,
            &f.channel,
            Hex32(parked.request_id()),
            Hex32(parked.hash()),
            verdict,
        )
    }

    fn grant(f: &Fixture) -> Grant {
        Grant {
            secrets: Vec::new(),
            keys: [f.key].into(),
            operations: [Operation::SignNostrEvent].into(),
            event_kinds: [0].into(),
            nip44_peers: Default::default(),
            bitcoin: None,
            limits: RequestLimits::default(),
        }
    }

    /// An approval comes only from the device's approver key approving this
    /// request; evaluated, it allows exactly the parked event.
    #[test]
    fn only_a_verified_approve_makes_an_approval() {
        let f = fixture();
        let parked = Parked::new(event(&f, "{}"), info(1), &f.channel).unwrap();
        let other = Parked::new(event(&f, "{}"), info(2), &f.channel).unwrap();
        // The transport key, another request's decision, a denial.
        let mut by_transport = decision(&f, &f.approver, &parked, Verdict::Approve);
        by_transport.sig = sig::sign_bip340(
            &f.transport,
            &sig::decision_digest(
                &f.channel,
                &f.device.device().approver,
                &parked.hash(),
                Verdict::Approve,
            ),
        );
        let (parked, why) =
            Approval::verify(&by_transport, &f.channel, &f.device, parked).unwrap_err();
        assert!(why.contains("signature"), "{why}");
        let _ = V1;
        let for_other = decision(&f, &f.approver, &other, Verdict::Approve);
        let (parked, _) = Approval::verify(&for_other, &f.channel, &f.device, parked).unwrap_err();
        let deny = decision(&f, &f.approver, &parked, Verdict::Deny);
        let (parked, why) = Approval::verify(&deny, &f.channel, &f.device, parked).unwrap_err();
        assert!(why.contains("denies"));

        let approve = decision(&f, &f.approver, &parked, Verdict::Approve);
        let approval = Approval::verify(&approve, &f.channel, &f.device, parked).unwrap();
        assert_eq!(approval.parked().request_id(), [1; 32]);
        let approval = approval.into_management().unwrap_err();
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        let (decision, approved) = evaluate_approved(approval, &grant(&f), &mut budgets, 0);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(approved.signature(), &approve.sig);
        assert_eq!(approved.device(), f.device.device());
        assert!(matches!(
            approved.into_parked().object(),
            ParkedObject::NostrEvent(e) if e.content == "{}"
        ));
    }

    /// A management change is applied through `into_management`, and
    /// evaluated as an agent request it is denied.
    #[test]
    fn a_management_approval_is_no_agent_request() {
        let f = fixture();
        let mut i = info(3);
        i.credential = None;
        i.reason = Reason::Management;
        let change = Change::Unfreeze {
            scope: keep_approval::change::Scope::All,
            epoch: keep_approval::change::Decimal(4),
        };
        let parked = Parked::new(ParkedObject::Management(change.clone()), i, &f.channel).unwrap();
        let approve = decision(&f, &f.approver, &parked, Verdict::Approve);
        let approval = Approval::verify(&approve, &f.channel, &f.device, parked).unwrap();
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        let parked = Parked::new(
            ParkedObject::Management(change.clone()),
            {
                let mut i = info(4);
                i.credential = None;
                i.reason = Reason::Management;
                i
            },
            &f.channel,
        )
        .unwrap();
        let approve2 = decision(&f, &f.approver, &parked, Verdict::Approve);
        let second = Approval::verify(&approve2, &f.channel, &f.device, parked).unwrap();
        let (d, _) = evaluate_approved(second, &grant(&f), &mut budgets, 0);
        assert_eq!(d, Decision::Deny(DenyReason::ManagementChange));
        let (approved, applied) = approval.into_management().unwrap();
        assert_eq!(applied, change);
        assert!(matches!(
            approved.parked().object(),
            ParkedObject::Management(c) if *c == change
        ));
    }

    /// Owed entries stop growing at the cap: more of a type already owed
    /// are counted on its newest, and say so when written.
    #[test]
    fn owed_entries_are_capped_and_repeats_counted() {
        let mut store = Store::default();
        for i in 0..MAX_OWED + 5 {
            store.owe(AuditEventType::AgentApproverFreeze, format!("freeze {i}"));
        }
        store.owe(AuditEventType::AgentApproverRemoved, "removed".into());
        store.owe(AuditEventType::AgentApproverRemoved, "removed again".into());
        assert_eq!(store.owed.len(), MAX_OWED + 1);
        let newest_freeze = &store.owed[MAX_OWED - 1];
        assert_eq!(newest_freeze.more, 5);
        assert!(
            newest_freeze
                .text()
                .starts_with(&format!("freeze {} (and 5 more", MAX_OWED - 1)),
            "{}",
            newest_freeze.text()
        );
        assert_eq!(store.owed[MAX_OWED].more, 1);
        assert_eq!(store.owed[0].text(), "freeze 0");
    }

    /// A request whose rumor would not fit a wrap is refused as too large to
    /// approve.
    #[test]
    fn a_request_too_large_to_wrap_is_refused() {
        let f = fixture();
        let big = "x".repeat(keep_approval::wrap::MAX_RUMOR_BYTES);
        let err = Parked::new(event(&f, &big), info(5), &f.channel).unwrap_err();
        assert!(err.to_string().contains("too large to approve"), "{err}");
    }
}
